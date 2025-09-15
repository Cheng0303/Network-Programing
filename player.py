import argparse, socket, json, time, threading, random, sys
from typing import List, Tuple, Optional
from protocol import send_json, recv_json, pretty_board
from game_logic import TicTacToeRecycling

# ---------- helpers ----------

UNUSABLE_HOSTS = {"0.0.0.0", "127.0.0.1", "::", "localhost", "", None}

def is_unusable_host(h: Optional[str]) -> bool:
    return h in UNUSABLE_HOSTS

def tcp_connect(host: str, port: int, timeout=5.0) -> socket.socket:
    """Prefer IPv4, then try IPv6; short per-attempt timeout; raise last error."""
    families = (socket.AF_INET, socket.AF_INET6)
    last_err = None
    per_try = min(timeout, 10.0)
    for fam in families:
        try:
            infos = socket.getaddrinfo(host, port, fam, socket.SOCK_STREAM)
        except OSError as e:
            last_err = e
            continue
        for *_, addr in infos:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(per_try)
            try:
                s.connect(addr)
                return s
            except OSError as e:
                last_err = e
                s.close()
    raise (last_err or TimeoutError(f"connect to {host}:{port} failed"))

def tcp_request(host: str, port: int, msg: dict) -> dict:
    s = tcp_connect(host, port)
    send_json(s, msg)
    resp = recv_json(s)
    s.close()
    return resp

# ---------- lobby ops ----------

def lobby_register(lobby_host, lobby_port, username, password):
    resp = tcp_request(lobby_host, lobby_port, {"type":"REGISTER","username":username,"password":password})
    print("[Lobby]", resp)

def lobby_login(lobby_host, lobby_port, username, password):
    resp = tcp_request(lobby_host, lobby_port, {"type":"LOGIN","username":username,"password":password})
    print("[Lobby]", resp)

# ---------- parsing ----------

def parse_hostport(s: str) -> Tuple[str,int]:
    if ":" not in s:
        raise ValueError("host:port expected")
    h, p = s.rsplit(":", 1)
    return h, int(p)

def parse_ports(pstr: str) -> List[int]:
    if "-" in pstr:
        a,b = pstr.split("-",1)
        a,b = int(a), int(b)
        return list(range(a, b+1))
    else:
        return [int(pstr)]

# ---------- UDP util ----------

def udp_send_and_wait(dst_host, dst_port, payload: dict, timeout=0.3) -> Tuple[bool, Tuple[str,int] or None, dict or None]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(json.dumps(payload).encode("utf-8"), (dst_host, dst_port))
        data, addr = s.recvfrom(2048)
        return True, addr, json.loads(data.decode("utf-8"))
    except socket.timeout:
        return False, None, None
    finally:
        s.close()

# ---------- scan/wait/invite ----------

def cmd_scan(hosts: List[str], ports: List[int], timeout=0.15):
    print(f"[Scan] Targets={len(hosts)} hosts × {len(ports)} ports")
    discovered = []
    for h in hosts:
        for p in ports:
            ok, addr, resp = udp_send_and_wait(h, p, {"type":"DISCOVER","from":"scanner"}, timeout=timeout)
            if ok and resp and resp.get("type")=="DISCOVER_ACK":
                print(f"  - Found {resp.get('player','?')} at {h}:{p}")
                discovered.append({"host":h,"port":p,"player":resp.get("player")})
    if not discovered:
        print("[Scan] No waiting players found.")
    return discovered

def cmd_wait(username: str, udp_port: int, auto_accept=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", udp_port))
    print(f"[Wait] {username} waiting on UDP {udp_port} ...")
    while True:
        data, addr = s.recvfrom(4096)
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        t = msg.get("type")
        if t == "DISCOVER":
            resp = {"type":"DISCOVER_ACK","player":username,"udp_port":udp_port}
            s.sendto(json.dumps(resp).encode("utf-8"), addr)

        elif t == "INVITE":
            print(f"[Wait] INVITE from {addr}: {msg}")
            decision = "ACCEPT" if auto_accept else (input("Accept invitation? [y/N] ").strip().lower()=="y")
            if decision is True:
                decision = "ACCEPT"
            elif decision is False:
                decision = "DECLINE"
            elif decision not in ("ACCEPT","DECLINE"):
                decision = "DECLINE"
            s.sendto(json.dumps({"type":"INVITE_REPLY","decision":decision}).encode("utf-8"), addr)
            if decision == "ACCEPT":
                inviter_ip = addr[0]  # 記住對方的來源 IP（保底用）
                print("[Wait] Accepted. Waiting for GAME_TCP ...")
                # wait for GAME_TCP
                while True:
                    s.settimeout(10.0)
                    try:
                        data2, addr2 = s.recvfrom(4096)
                    except socket.timeout:
                        print("[Wait] Timeout waiting for GAME_TCP. Back to waiting for invites.")
                        s.settimeout(None)
                        break
                    try:
                        msg2 = json.loads(data2.decode("utf-8"))
                    except Exception:
                        continue
                    if msg2.get("type") == "GAME_TCP":
                        host = msg2.get("host")
                        port = int(msg2.get("port"))
                        # 若對方送了 0.0.0.0/localhost，就用對方的來源 IP 當連線目標
                        if is_unusable_host(host):
                            # 先用邀請者 IP（更可信），退而求其次用這包訊息的來源 IP
                            host = inviter_ip or addr2[0]
                        tcp_target = (host, port)
                        print(f"[Wait] Got TCP target: {tcp_target}")
                        s.close()
                        run_guest(username, tcp_target[0], tcp_target[1])
                        return
        else:
            pass

def run_host(username: str, bind_host: str, tcp_port: int, peer_udp: Tuple[str,int], advertise_host: Optional[str]=None):
    """Host side: listen TCP, then tell guest how to reach us via UDP (GAME_TCP)."""
    # TCP server
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind((bind_host, tcp_port))
    serv.listen(1)
    print(f"[Host] TCP listening on {bind_host}:{tcp_port}")

    # Decide what host to advertise to the peer (不要用 0.0.0.0/localhost)
    adv_host = advertise_host or bind_host
    if is_unusable_host(adv_host):
        adv_host = peer_udp[0]  # 用對方看到的我們的來源 IP

    # notify peer via UDP（回到對方剛剛回覆 INVITE 的來源）
    uh, up = peer_udp
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.sendto(json.dumps({"type":"GAME_TCP","host":adv_host,"port":tcp_port}).encode("utf-8"), (uh, up))
    us.close()
    print(f"[Host] Advertised TCP target: {adv_host}:{tcp_port}")

    conn, addr = serv.accept()
    print(f"[Host] Peer connected from {addr}")

    # Game
    game = TicTacToeRecycling()
    # host is 'X' and starts
    start_msg = {"type":"WELCOME","mark":"X","first":"X","rule":"recycle-3"}
    conn.sendall((json.dumps(start_msg)+"\n").encode("utf-8"))
    print("[Game] You are 'X'. You go first.")
    while True:
        if game.turn == "X":
            print(pretty_board(game.board_str()))
            pos = prompt_move(game)
            ok, info = game.apply_move("X", pos)
            if not ok:
                print("[Game] Illegal move:", info)
                continue
            # send state to peer
            send_line(conn, {"type":"STATE","board":game.board_str(),"turn":game.turn,"last":pos,"recycled":info.get("recycled")})
            if info.get("winner"):
                send_line(conn, {"type":"GAME_OVER","winner":"X"})
                print(pretty_board(game.board_str()))
                print("[Game] You WIN!")
                break
        else:
            # Peer turn
            send_line(conn, {"type":"YOUR_TURN"})
            msg = recv_json(conn)
            if not msg:
                print("[Host] Peer disconnected.")
                break
            if msg.get("type") != "MOVE":
                print("[Host] Unexpected:", msg)
                continue
            pos = int(msg.get("pos"))
            ok, info = game.apply_move("O", pos)
            if not ok:
                send_line(conn, {"type":"ERROR","reason":info.get("reason","illegal")})
                continue
            send_line(conn, {"type":"STATE","board":game.board_str(),"turn":game.turn,"last":pos,"recycled":info.get("recycled")})
            if info.get("winner"):
                send_line(conn, {"type":"GAME_OVER","winner":"O"})
                print(pretty_board(game.board_str()))
                print("[Game] You LOSE.")
                break
    conn.close()
    serv.close()

# ---------- line/json helpers ----------

def send_line(sock, obj):
    sock.sendall((json.dumps(obj)+"\n").encode("utf-8"))

def recv_line(sock):
    buf = []
    while True:
        b = sock.recv(1)
        if not b:
            break
        if b == b"\n":
            break
        buf.append(b)
    return b"".join(buf).decode("utf-8") if buf else ""

# ---------- gameplay ----------

def prompt_move(game: TicTacToeRecycling) -> int:
    while True:
        raw = input("Your move (0-8; positions are):\n 0 1 2\n 3 4 5\n 6 7 8\n> ").strip()
        try:
            pos = int(raw)
        except:
            print("Please enter a number 0-8.")
            continue
        if 0 <= pos < 9 and game.is_legal(pos):
            return pos
        print("Illegal cell. Try again.")

def run_guest(username: str, host: str, port: int):
    print(f"[Guest] Connecting to {host}:{port} ...")
    s = tcp_connect(host, port)
    # wait for WELCOME
    msg = recv_json(s)
    if not msg or msg.get("type") != "WELCOME":
        print("[Guest] Bad welcome:", msg)
        s.close()
        return
    print(f"[Game] You are 'O'. Host is 'X'. Rule: recycle-3. First: {msg.get('first','X')}")
    while True:
        msg = recv_json(s)
        if not msg:
            print("[Guest] Disconnected.")
            break
        t = msg.get("type")
        if t == "YOUR_TURN":
            pos = prompt_move_guest()
            send_line(s, {"type":"MOVE","pos":pos})
        elif t == "STATE":
            print(pretty_board(msg.get("board",""*9)))
            if msg.get("recycled") is not None:
                print(f"[Info] Recycled cell: {msg['recycled']}")
        elif t == "ERROR":
            print("[Guest] ERROR:", msg.get("reason"))
        elif t == "GAME_OVER":
            winner = msg.get("winner")
            if winner == "O":
                print("[Game] You WIN!")
            else:
                print("[Game] You LOSE.")
            break
        elif t == "WELCOME":
            continue
        else:
            print("[Guest] Unknown:", msg)
    s.close()

def prompt_move_guest() -> int:
    while True:
        raw = input("Your move (0-8; positions are):\n 0 1 2\n 3 4 5\n 6 7 8\n> ").strip()
        try:
            pos = int(raw)
        except:
            print("Please enter a number 0-8.")
            continue
        if 0 <= pos < 9:
            return pos
        print("Out of range 0-8.")

# ---------- CLI ----------

def cmd_invite(username: str, target_host: str, target_port: int, tcp_bind_host: str, tcp_port: int, tcp_advertise_host: Optional[str]):
    print(f"[Invite] Sending INVITE to {target_host}:{target_port} ...")
    ok, addr, resp = udp_send_and_wait(target_host, target_port, {"type":"INVITE","from":username}, timeout=3.0)
    if not ok or not resp:
        print("[Invite] Declined or timeout.")
        return
    if resp.get("type")=="INVITE_REPLY" and resp.get("decision")=="ACCEPT":
        print("[Invite] Accepted. Hosting TCP...")
        # 用「對方回 INVITE 的來源位址」作為後續回報的 UDP 目標，避免 hostname/NAT 造成偏差
        peer_udp = addr if addr else (target_host, target_port)
        run_host(username, tcp_bind_host, tcp_port, peer_udp, advertise_host=tcp_advertise_host)
    else:
        print("[Invite] Declined:", resp)

def main():
    ap = argparse.ArgumentParser(description="Player client (login/scan/wait/invite/game)")
    ap.add_argument("--lobby", help="host:port of lobby", default=None)
    ap.add_argument("--username", "--name", dest="username", required=True)
    ap.add_argument("--password", help="password for lobby ops", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sreg = sub.add_parser("register")
    slog = sub.add_parser("login")

    swait = sub.add_parser("wait")
    swait.add_argument("--udp-port", type=int, required=True)
    swait.add_argument("--auto-accept", action="store_true")

    sscan = sub.add_parser("scan")
    sscan.add_argument("--hosts", default="linux1.cs.nycu.edu.tw,linux2.cs.nycu.edu.tw,linux3.cs.nycu.edu.tw,linux4.cs.nycu.edu.tw")
    sscan.add_argument("--ports", default="10001-10020")
    sscan.add_argument("--timeout", type=float, default=0.15)

    sinv = sub.add_parser("invite")
    sinv.add_argument("--target", required=True, help="host:udp_port")
    sinv.add_argument("--tcp-bind-host", default="0.0.0.0", help="listen host/IP (0.0.0.0 to listen on all)")
    sinv.add_argument("--tcp-port", type=int, default=5001)
    sinv.add_argument("--tcp-advertise-host", default=None,
                      help="host/IP to tell the peer to connect to; "
                           "omit to auto-use the IP seen by the peer")

    args = ap.parse_args()

    # lobby host:port parse if needed
    lobby_host = lobby_port = None
    if args.cmd in ("register","login"):
        if not args.lobby:
            print("Use --lobby host:port for register/login")
            sys.exit(1)
        lobby_host, lobby_port = parse_hostport(args.lobby)

    if args.cmd == "register":
        if not args.password:
            print("Use --password for register")
            sys.exit(1)
        lobby_register(lobby_host, lobby_port, args.username, args.password)

    elif args.cmd == "login":
        if not args.password:
            print("Use --password for login")
            sys.exit(1)
        lobby_login(lobby_host, lobby_port, args.username, args.password)

    elif args.cmd == "wait":
        cmd_wait(args.username, args.udp_port, auto_accept=args.auto_accept)

    elif args.cmd == "scan":
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
        ports = parse_ports(args.ports)
        cmd_scan(hosts, ports, timeout=args.timeout)

    elif args.cmd == "invite":
        th, tp = parse_hostport(args.target)
        cmd_invite(args.username, th, tp, args.tcp_bind_host, args.tcp_port, args.tcp_advertise_host)

if __name__ == "__main__":
    main()
