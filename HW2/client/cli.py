# client/cli.py
import argparse, socket, sys, json, subprocess, os, threading, queue, time, signal, hashlib, collections
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from common.framing import send_json, recv_json

GUI_PATH = os.path.join(os.path.dirname(__file__), "gui.py")

# ---------------- State ----------------
class State:
    def __init__(self):
        self.user_id = None
        self.room = None                  # 最新房間物件（含 memberUsers/hostName）
        self.invites = collections.deque()# 邀請佇列（僅在有 modal 時塞進來）
        self.modal = None                 # 目前顯示中的 modal（例如邀請）
        self.form = None                  # {"name":..., "fields":[...], "idx":0, "values":{}}
        self.messages = collections.deque(maxlen=64)  # 訊息緩衝；印出後會清空（drain）
        self.launched_keys = set()        # 避免重複啟 GUI
        self.dirty_menu = True            # 是否需要重印選單
        self.alive = True                 # 全域結束旗標
        self.lock = threading.Lock()
        # List Rooms 防連印
        self._rooms_hash = None
        self._rooms_last_print = 0.0
        # 去重：避免同一邀請彈兩次（key: (roomId, fromUserId)）
        self._invite_seen = set()

    def push_msg(self, text):
        with self.lock:
            for line in (text.splitlines() or [""]):
                self.messages.append(line)
            self.dirty_menu = True

    def drain_msgs(self):
        with self.lock:
            msgs = list(self.messages)
            self.messages.clear()
            return msgs

# ---------------- Utilities ----------------
def safe_print(*a, **k):
    k.setdefault("flush", True)
    print(*a, **k)

def rooms_hash(rooms):
    try:
        return hashlib.sha256(json.dumps(rooms, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    except Exception:
        return str(time.time())

def launch_gui_async(state: State, data, user_id):
    key = (data.get("roomId"), data.get("port"))
    if key in state.launched_keys:
        return
    state.launched_keys.add(key)

    def work():
        try:
            time.sleep(0.35)  # 等 GS 起來穩定一點
            subprocess.Popen([
                sys.executable, GUI_PATH,
                "--host", data["host"], "--port", str(data["port"]),
                "--room-id", str(data["roomId"]),
                "--room-token", data["roomToken"],
                "--user-id", str(user_id),
            ])
            state.push_msg("[Lobby] Game client launched.")
        except Exception as e:
            state.push_msg(f"[Lobby] Launch GUI failed: {e}")

    threading.Thread(target=work, daemon=True).start()

def extract_invite_fields(msg):
    """
    從 INVITED 事件裡，穩健地拿 rid 與 host 顯示名。
    支援: {room:{id,hostUserId,hostName,...}} 或 {roomId, hostUserId, hostName}
    """
    room = (msg.get("room") or {}) if isinstance(msg.get("room"), dict) else {}
    rid = room.get("id") or msg.get("roomId")
    host = room.get("hostName") or room.get("hostUserId") or msg.get("hostName") or msg.get("hostUserId")
    return rid, host, room

# ---------------- Rendering ----------------
def print_messages(state: State):
    msgs = state.drain_msgs()
    if not msgs: return
    safe_print("— Messages —")
    for m in msgs: safe_print(m)

def print_lobby_menu():
    safe_print("===== Lobby Menu =====")
    safe_print("1) List Users  2) List Rooms  3) Create Room  4) Join Room  5) Logout  6) Spectate  0) Quit")

def print_room_menu(state: State):
    r = state.room or {}
    rid = r.get("id")
    names = [u.get("name") for u in (r.get("memberUsers") or [])] or r.get("members")
    host = r.get("hostName") or r.get("hostUserId")
    safe_print(f"===== Room {rid} (host={host}, members={names}) =====")
    if r.get("hostUserId") == state.user_id:
        safe_print("1) Invite user  2) Change rule  3) Start match  4) Leave room")
    else:
        safe_print("1) Invite user  2) Leave room")

def print_modal(state: State):
    m = state.modal
    if not m: return False
    if m.get("type") == "invite":
        rid = m.get("roomId")
        host = m.get("host")
        safe_print(f"=== Invitation ===")
        safe_print(f"You were invited to room {rid} (host: {host}). Accept? [y/n]")
        # 只顯示真正「等待中」的額外筆數
        pending = len(state.invites)
        if pending > 0:
            safe_print(f"(+{pending} more pending)")
        safe_print("input> ", end="")
        return True
    return False

def print_form(state: State):
    form = state.form
    if not form: return False
    fields = form["fields"]
    idx = form["idx"]
    cur = fields[idx]
    title_map = {
        "create_room": "Create Room",
        "join_room": "Join Room",
        "invite": "Invite User",
        "set_rule": "Change Rule",
        "spectate": "Spectate Room",
    }
    title = title_map.get(form["name"], form["name"])
    safe_print(f"=== {title} ({idx+1}/{len(fields)}) ===")
    default = cur.get("default")
    if default is not None:
        safe_print(f"{cur['prompt']} [{default}]")
    else:
        safe_print(cur["prompt"])
    safe_print("input> ", end="")
    return True

def refresh_menu(state: State):
    """
    印出順序：
    1) 先印訊息（drain）
    2) 若有 modal（邀請等）→ 顯示並 return
    3) 若有表單 → 顯示並 return
    4) 否則印 Lobby 或 Room 選單
    """
    print_messages(state)
    if state.modal:
        print_modal(state); state.dirty_menu = False; return
    if state.form:
        print_form(state); state.dirty_menu = False; return
    if not state.room or not state.room.get("members"):
        print_lobby_menu(); safe_print("choice> ", end="")
    else:
        print_room_menu(state); safe_print("choice> ", end="")
    state.dirty_menu = False

# ---------------- Network receiver ----------------
def receiver(sock, inbox: queue.Queue, state: State):
    while state.alive:
        msg = recv_json(sock)
        if not msg:
            inbox.put({"type": "_DISCONNECTED"})
            break
        t = msg.get("type")

        if t == "ROOM_UPDATE":
            state.room = msg.get("room")
            # 進/離房後，把同房的 pending 邀請清掉；避免髒資料
            rid = state.room.get("id") if state.room else None
            if rid is not None:
                state.invites = collections.deque([i for i in state.invites if i.get("roomId") != rid])
                state._invite_seen = {k for k in state._invite_seen if k[0] != rid}
                if state.modal and state.modal.get("type") == "invite" and state.modal.get("roomId") == rid:
                    state.modal = None
            state.dirty_menu = True
            inbox.put({"type": "_NOP"})

        elif t == "INVITED":
            rid, host, room = extract_invite_fields(msg)
            if not rid:
                state.push_msg("[Invite] Received an invite without room id. Ignored.")
                state.dirty_menu = True
                inbox.put({"type": "_NOP"})
                continue

            # 同一來源對同一房的重複邀請去重
            key = (rid, msg.get("fromUserId"))
            if key in state._invite_seen:
                # already seen -> ignore duplicate
                state.dirty_menu = True
                inbox.put({"type": "_NOP"})
                continue
            state._invite_seen.add(key)

            inv = {"type":"invite", "roomId": rid, "host": host, "room": room, "fromUserId": msg.get("fromUserId")}
            # 修正：只有在「目前已有 modal」時，才把新邀請塞進佇列
            if state.modal:
                state.invites.append(inv)
            else:
                state.modal = inv
            state.dirty_menu = True
            inbox.put({"type": "_NOP"})

        elif t == "MATCH_READY":
            state.push_msg("[Lobby] MATCH_READY received.")
            launch_gui_async(state, msg, state.user_id)
            state.dirty_menu = True
            inbox.put({"type": "_NOP"})

        elif t == "MATCH_RESULT":
            rid = msg.get("roomId")
            winner = msg.get("winnerUserId")
            draw = msg.get("draw", False)
            if draw or winner is None:
                safe_print(f"[Room {rid}] Match finished: DRAW")
            else:
                safe_print(f"[Room {rid}] Match finished: winner userId={winner}")
            for r in msg.get("results", []):
                safe_print(f" - uid={r.get('userId')}  alive={r.get('alive')}  lines={r.get('lines')}  score={r.get('score')}  maxCombo={r.get('maxCombo')}")

        elif t == "ROOM_CLOSED":
            rid = msg.get("roomId")
            state.room = None
            state.push_msg(f"Room {rid} closed by host.")
            state.dirty_menu = True
            inbox.put({"type": "_NOP"})

        elif t == "SESSION_KICK":
            reason = msg.get("reason", "duplicate login")
            safe_print(f"\n[Warning] You have been signed out: {reason}")
            try: sock.close()
            except Exception: pass
            os._exit(0)

        else:
            inbox.put(msg)

# ---------------- StdIn thread ----------------
def stdin_thread(lineq: queue.Queue, alive_ref):
    while alive_ref():
        try:
            line = sys.stdin.readline()
            if not line: break
            lineq.put(line.rstrip("\r\n"))
        except KeyboardInterrupt:
            break

# ---------------- Forms ----------------
def start_form(state: State, name, fields):
    state.form = {"name": name, "fields": fields, "idx": 0, "values": {}}
    state.dirty_menu = True

def handle_form_line(state: State, line: str, send):
    form = state.form
    if not form: return
    fields = form["fields"]; idx = form["idx"]; cur = fields[idx]
    key = cur["key"]; val = (line or "").strip()
    if not val and cur.get("default") is not None:
        val = cur["default"]
    ty = cur.get("type", "str")
    if ty == "int":
        try: val = int(val)
        except Exception:
            state.push_msg("Invalid number."); state.dirty_menu = True; return
    elif ty == "choice":
        choices = cur.get("choices", [])
        if val not in choices:
            state.push_msg(f"Invalid choice. Use one of {choices}.")
            state.dirty_menu = True
            return

    form["values"][key] = val
    form["idx"] += 1

    if form["idx"] >= len(fields):
        v = form["values"]; name = form["name"]
        if name == "create_room":
            send({"type": "CREATE_ROOM", "name": v["name"], "visibility": v["visibility"], "rule": v["rule"]})
            state.push_msg("Creating room...")
        elif name == "join_room":
            send({"type": "JOIN_ROOM", "roomId": v["roomId"]})
            state.push_msg(f"(joining room {v['roomId']})")
        elif name == "invite":
            rid = state.room["id"]
            send({"type": "INVITE", "roomId": rid, "targetUserId": v["userId"]})
            state.push_msg(f"Invited user {v['userId']}.")
        elif name == "set_rule":
            rid = state.room["id"]
            send({"type": "SET_RULE", "roomId": rid, "rule": v["rule"]})
            state.push_msg(f"Rule updated to {v['rule']}.")
        elif name == "spectate":
            rid = v["roomId"]
            send({"type":"SPECTATE", "roomId": rid})
            state.push_msg(f"Request spectate room {rid}...")
        state.form = None

    state.dirty_menu = True

# ---------------- Modal (invite) ----------------
def handle_modal_line(state: State, line: str, send):
    m = state.modal
    if not m: return False
    if m.get("type") == "invite":
        ans = (line or "").strip().lower()
        rid = m.get("roomId")  # 已在彈窗建立時保證存在
        if ans.startswith("y"):
            send({"type": "ACCEPT_INVITE", "roomId": rid})
            state.push_msg(f"Accepted invite to room {rid}.")
        else:
            state.push_msg(f"Ignored invite to room {rid}.")
        state.modal = None
        # 取下一筆等待中的邀請（如果有）
        if state.invites:
            nxt = state.invites.popleft()
            state.modal = nxt
        state.dirty_menu = True
        return True
    return False

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lobby", default="127.0.0.1:12000")
    args = ap.parse_args()
    host, port = args.lobby.split(":"); port = int(port)

    s = socket.create_connection((host, port))
    safe_print("Connected to Lobby.")

    state = State()

    # --- SIGINT / SIGTERM: 立即結束，關 socket 與 threads ---
    def stop_all(*_):
        if not state.alive: return
        state.alive = False
        try: s.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: s.close()
        except Exception: pass
        safe_print("\n[CLI] terminated.")
        os._exit(0)

    signal.signal(signal.SIGINT, stop_all)
    try: signal.signal(signal.SIGTERM, stop_all)
    except Exception: pass

    def alive_ref(): return state.alive
    def send(obj): send_json(s, obj)
    def rpc(obj): send_json(s, obj); return recv_json(s)

    # ---- Auth (同步) ----
    while True:
        safe_print("\n1) Register  2) Login  0) Quit")
        safe_print("choice> ", end="")
        ch = sys.stdin.readline().strip()
        if ch == "1":
            name = input("name: "); pw = input("password: ")
            r = rpc({"type": "REGISTER", "name": name, "password": pw})
            safe_print(r)
        elif ch == "2":
            x = input("name: "); pw = input("password: ")
            r = rpc({"type": "LOGIN", "name": x, "password": pw})
            safe_print(r)
            if r and r.get("type") == "OK":
                user = r.get("user") or {}; state.user_id = user.get("id"); break
        elif ch == "0":
            try: s.close()
            except Exception: pass
            return

    # ---- Async threads ----
    inbox = queue.Queue()
    lineq = queue.Queue()
    t_recv = threading.Thread(target=receiver, args=(s, inbox, state), daemon=True)
    t_in = threading.Thread(target=stdin_thread, args=(lineq, alive_ref), daemon=True)
    t_recv.start(); t_in.start()

    state.dirty_menu = True

    def handle_inbox():
        handled = False
        while True:
            try: msg = inbox.get_nowait()
            except queue.Empty: break
            handled = True
            t = msg.get("type")
            if t == "_DISCONNECTED":
                safe_print("Disconnected from lobby."); stop_all(); break
            elif t == "ERR":
                text = msg.get("msg") or msg.get("detail") or str(msg)
                state.push_msg(f"ERROR: {text}")
            elif t == "OK":
                if "rooms" in msg:
                    rooms = msg["rooms"]
                    now = time.time(); h = rooms_hash(rooms)
                    if h != state._rooms_hash or (now - state._rooms_last_print) > 0.6:
                        state._rooms_hash = h; state._rooms_last_print = now
                        safe_print("Public rooms:")
                        for r in rooms:
                            names = [u.get("name") for u in (r.get("memberUsers") or [])] or r.get("members")
                            host = r.get("hostName") or r.get("hostUserId")
                            safe_print(f"  id={r.get('id')}  members={names}  host={host}  rule={r.get('rule')}")
                        state.dirty_menu = True
                elif "users" in msg:
                    users = msg["users"]
                    if not users: safe_print("No users online.")
                    else:
                        safe_print("Online users:")
                        for u in users: safe_print(f"  id={u.get('id')}  name={u.get('name')}")
                    state.dirty_menu = True
                else:
                    text = msg.get("msg") or "OK"
                    state.push_msg(text)
            elif t == "ROOM_NOTICE":
                ev = msg.get("event"); rid = msg.get("roomId"); uid = msg.get("userId")
                state.push_msg(f"[Room {rid}] {ev} by user {uid}")
            elif t == "_NOP":
                pass
            elif t == "INFO":
                state.push_msg(msg.get("text"))
        return handled

    while state.alive:
        did = handle_inbox()
        if state.dirty_menu or did:
            refresh_menu(state)

        try: line = lineq.get(timeout=0.05)
        except queue.Empty: continue

        # 先處理 modal（例如邀請 y/n）
        if state.modal:
            if handle_modal_line(state, line, send):
                refresh_menu(state)
            continue

        # 表單
        if state.form:
            handle_form_line(state, line, send)
            refresh_menu(state)
            continue

        # 一般選單
        if not state.room or not state.room.get("members"):
            if line == "1":
                send({"type": "LIST_USERS"})
            elif line == "2":
                send({"type": "LIST_ROOMS"})
            elif line == "3":
                start_form(state, "create_room", [
                    {"key": "name", "prompt": "room name:", "type": "str"},
                    {"key": "visibility", "prompt": "visibility (public/private):", "type": "choice",
                     "choices": ["public", "private"], "default": "public"},
                    {"key": "rule", "prompt": "rule (timed/survival/lines):", "type": "choice",
                     "choices": ["timed", "survival", "lines"], "default": "timed"},
                ])
                refresh_menu(state)
            elif line == "4":
                start_form(state, "join_room", [
                    {"key": "roomId", "prompt": "roomId:", "type": "int"},
                ])
                refresh_menu(state)
            elif line == "5":
                send({"type": "LOGOUT"}); safe_print("Logged out."); os._exit(0)
            elif line == "6":
                start_form(state, "spectate", [
                    {"key": "roomId", "prompt": "roomId to spectate:", "type": "int"},
                ])
                refresh_menu(state)
            elif line == "0":
                safe_print("Bye"); os._exit(0)
            else:
                state.dirty_menu = True; refresh_menu(state)
        else:
            rid = state.room.get("id"); host_id = state.room.get("hostUserId"); me = state.user_id
            if host_id == me:
                if line == "1":
                    start_form(state, "invite", [
                        {"key": "userId", "prompt": "targetUserId:", "type": "int"},
                    ]); refresh_menu(state)
                elif line == "2":
                    start_form(state, "set_rule", [
                        {"key": "rule", "prompt": "new rule (timed/survival/lines):", "type": "choice",
                         "choices": ["timed", "survival", "lines"], "default": "timed"},
                    ]); refresh_menu(state)
                elif line == "3":
                    send({"type": "START_MATCH", "roomId": rid})
                    state.push_msg("Starting match..."); state.dirty_menu = True
                elif line == "4":
                    send({"type": "LEAVE_ROOM", "roomId": rid})
                    state.room = None; state.push_msg("Left room."); state.dirty_menu = True
                else:
                    state.dirty_menu = True
                refresh_menu(state)
            else:
                if line == "1":
                    start_form(state, "invite", [
                        {"key": "userId", "prompt": "targetUserId:", "type": "int"},
                    ]); refresh_menu(state)
                elif line == "2":
                    send({"type": "LEAVE_ROOM", "roomId": rid})
                    state.room = None; state.push_msg("Left room."); state.dirty_menu = True
                    refresh_menu(state)
                else:
                    state.dirty_menu = True; refresh_menu(state)

if __name__ == "__main__":
    main()
