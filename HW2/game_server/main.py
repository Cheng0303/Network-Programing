import argparse, socket, threading, time, sys, os, json, random
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from common.framing import send_json, recv_json

# ======== Utils ========
def log(*a): print("[GS]", *a, flush=True)

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--room-id", type=int, required=True)
    ap.add_argument("--room-token", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--rule", default="timed")  # timed/survival/lines
    ap.add_argument("--match-id", default=None)
    ap.add_argument("--lobby-host", default="127.0.0.1")
    ap.add_argument("--lobby-port", type=int, default=12000)
    ap.add_argument("--server-secret", default="dev-secret")
    return ap.parse_args()

# piece 編碼：0=空；1~7 = I,O,T,S,Z,J,L
PIECE_CODE = {"I":1,"O":2,"T":3,"S":4,"Z":5,"J":6,"L":7}

# SRS-ish 形狀
SHAPES = {
    "I":[[(0,1),(1,1),(2,1),(3,1)],[(2,0),(2,1),(2,2),(2,3)],[(0,2),(1,2),(2,2),(3,2)],[(1,0),(1,1),(1,2),(1,3)]],
    "O":[[(1,0),(2,0),(1,1),(2,1)]]*4,
    "T":[[(1,0),(0,1),(1,1),(2,1)],[(1,0),(1,1),(2,1),(1,2)],[(0,1),(1,1),(2,1),(1,2)],[(1,0),(0,1),(1,1),(1,2)]],
    "S":[[(1,0),(2,0),(0,1),(1,1)],[(1,0),(1,1),(2,1),(2,2)],[(1,1),(2,1),(0,2),(1,2)],[(0,0),(0,1),(1,1),(1,2)]],
    "Z":[[(0,0),(1,0),(1,1),(2,1)],[(2,0),(1,1),(2,1),(1,2)],[(0,1),(1,1),(1,2),(2,2)],[(1,0),(0,1),(1,1),(0,2)]],
    "J":[[(0,0),(0,1),(1,1),(2,1)],[(1,0),(2,0),(1,1),(1,2)],[(0,1),(1,1),(2,1),(2,2)],[(1,0),(1,1),(0,2),(1,2)]],
    "L":[[(2,0),(0,1),(1,1),(2,1)],[(1,0),(1,1),(1,2),(2,2)],[(0,1),(1,1),(2,1),(0,2)],[(0,0),(1,0),(1,1),(1,2)]],
}

KICK_TESTS = [(0,0), (-1,0), (1,0), (0,-1), (-2,0), (2,0)]

def rle_encode_board(board):
    flat = []
    for y in range(20):
        for x in range(10):
            flat.append(board[y][x])
    out = []
    i = 0
    n = len(flat)
    while i < n:
        v = flat[i]; j = i+1
        while j < n and flat[j] == v and (j-i) < 999:
            j += 1
        out.append(f"{v}x{j-i}")
        i = j
    return ",".join(out)

# ======== Game Model ========
class Bag7:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.bag = []
    def next(self):
        if not self.bag:
            self.bag = list("IOTSZJL")
            self.rng.shuffle(self.bag)
        return self.bag.pop()

class Piece:
    def __init__(self, kind, x, y, rot=0):
        self.kind = kind; self.x = x; self.y = y; self.rot = rot % 4
    def cells(self):
        return [(self.x+dx, self.y+dy) for (dx,dy) in SHAPES[self.kind][self.rot]]

class Player:
    def __init__(self, user_id, rng_seed):
        self.uid = user_id
        self.board = [[0]*10 for _ in range(20)]
        self.queue = []; self.hold = None; self.can_hold = True
        self.score = 0; self.lines = 0; self.level = 1
        self.alive = True
        self.cur = None
        self.last_drop_ms = 0
        self.inbox = []
        self.bag = Bag7(rng_seed)

    def spawn(self):
        if len(self.queue) < 5:
            while len(self.queue) < 5:
                self.queue.append(self.bag.next())
        k = self.queue.pop(0)
        self.cur = Piece(k, 3, -2, 0)
        self.can_hold = True
        if self._collides(self.cur):
            self.alive = False

    def _collides(self, piece):
        for (x,y) in piece.cells():
            if x < 0 or x >= 10: return True
            if y >= 20: return True
            if y >= 0 and self.board[y][x] != 0: return True
        return False

    def _try_move(self, dx, dy):
        if not self.cur: return
        np = Piece(self.cur.kind, self.cur.x+dx, self.cur.y+dy, self.cur.rot)
        if not self._collides(np):
            self.cur = np; return True
        return False

    def _try_rotate(self, dr):
        if not self.cur: return
        nr = (self.cur.rot + dr) % 4
        base = Piece(self.cur.kind, self.cur.x, self.cur.y, nr)
        for (kx,ky) in KICK_TESTS:
            cand = Piece(base.kind, base.x+kx, base.y+ky, base.rot)
            if not self._collides(cand):
                self.cur = cand; return True
        return False

    def _lock(self):
        code = PIECE_CODE[self.cur.kind]
        for (x,y) in self.cur.cells():
            if 0 <= y < 20 and 0 <= x < 10:
                self.board[y][x] = code
        cleared = 0
        new_board = []
        for y in range(20):
            if all(self.board[y][x] != 0 for x in range(10)):
                cleared += 1
            else:
                new_board.append(self.board[y][:])
        for _ in range(cleared):
            new_board.insert(0, [0]*10)
        self.board = new_board
        if cleared == 1: self.score += 100
        elif cleared == 2: self.score += 300
        elif cleared == 3: self.score += 500
        elif cleared >= 4: self.score += 800
        self.lines += cleared
        self.spawn()

    def soft_drop(self):
        if not self.cur: return
        if not self._try_move(0, 1):
            self._lock()
        else:
            self.score += 1

    def hard_drop(self):
        if not self.cur: return
        dist = 0
        while self._try_move(0,1):
            dist += 1
        self.score += 2*dist
        self._lock()

    def hold_swap(self):
        if not self.cur or not self.can_hold: return
        k = self.cur.kind
        if self.hold is None:
            self.hold = k; self.spawn()
        else:
            self.cur = Piece(self.hold, 3, -2, 0)
            self.hold = k
            if self._collides(self.cur):
                self.alive = False
        self.can_hold = False

    def step_inputs(self):
        inbox, self.inbox = self.inbox, []
        for act in inbox:
            if   act == "L":  self._try_move(-1,0)
            elif act == "R":  self._try_move( 1,0)
            elif act == "CW": self._try_rotate(1)
            elif act == "CCW":self._try_rotate(-1)
            elif act == "SD": self.soft_drop()
            elif act == "HD": self.hard_drop()
            elif act == "HOLD": self.hold_swap()

    def tick_gravity(self, now_ms, drop_ms):
        if not self.cur or not self.alive: return
        if now_ms - self.last_drop_ms >= drop_ms:
            self.last_drop_ms = now_ms
            if not self._try_move(0,1):
                self._lock()

    def snapshot(self, now_ms):
        board_rle = rle_encode_board(self.board)
        active = {"shape": self.cur.kind if self.cur else None,
                  "x": self.cur.x if self.cur else None,
                  "y": self.cur.y if self.cur else None,
                  "rot": self.cur.rot if self.cur else None}
        next3 = self.queue[:3]
        return {
            "type":"SNAPSHOT",
            "tick": now_ms,
            "userId": self.uid,
            "boardRLE": board_rle,
            "active": active,
            "hold": self.hold,
            "next": next3,
            "score": self.score,
            "lines": self.lines,
            "level": self.level,
            "alive": self.alive,
            "at": int(time.time())
        }

# ======== Game Server ========
class GameServer:
    def __init__(self, host, port, room_id, room_token, seed, rule, match_id, lobby_host, lobby_port, server_secret):
        self.host, self.port = host, port
        self.room_id, self.room_token = int(room_id), str(room_token)
        self.seed, self.rule = int(seed), rule
        self.match_id = match_id
        self.lobby_host, self.lobby_port = lobby_host, int(lobby_port)
        self.server_secret = server_secret
        self.sock = None
        self.lock = threading.Lock()
        self.clients = {}   # userId -> {"sock":s, "role":"P1"/"P2", "player":Player}
        self.running = True
        self.gravity = {"mode":"fixed","dropMs":600}
        self.start_ms = int(time.time()*1000)
        self.match_seconds = 60 if (rule=="timed") else 600
        self.broadcast_interval_ms = 120

    # ---- net ----
    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(8)
        s.settimeout(1.0)
        self.sock = s
        log(f"listening on {self.host}:{self.port}, room={self.room_id}, rule={self.rule}, matchId={self.match_id}")

        threading.Thread(target=self.accept_loop, daemon=True).start()
        threading.Thread(target=self.game_loop, daemon=True).start()
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            log("KeyboardInterrupt -> shutting down")
        finally:
            self.running = False
            try: self.sock.close()
            except Exception: pass
            with self.lock:
                for ent in list(self.clients.values()):
                    try: ent["sock"].close()
                    except Exception: pass

    def accept_loop(self):
        while self.running:
            try:
                c, a = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handle_client, args=(c, a), daemon=True).start()

    def handle_client(self, s, addr):
        s.settimeout(10.0)
        uid = None
        try:
            hello = recv_json(s)
            log("conn", addr, "hello:", hello)
            if not hello or hello.get("type") != "HELLO": s.close(); return
            if int(hello.get("roomId")) != self.room_id: s.close(); return
            if hello.get("roomToken") != self.room_token: s.close(); return
            uid = int(hello.get("userId"))
            with self.lock:
                role = "P1" if "P1" not in [v["role"] for v in self.clients.values()] else "P2"
                player = Player(uid, self.seed)
                player.spawn()
                self.clients[uid] = {"sock": s, "role": role, "player": player}
            welcome = {
                "type":"WELCOME",
                "role": role,
                "roomId": self.room_id,
                "seed": self.seed,
                "bagRule": "7bag",
                "gravityPlan": self.gravity,
                "rule": self.rule,
            }
            send_json(s, welcome)
            s.settimeout(None)
            while self.running:
                msg = recv_json(s)
                if not msg: break
                if msg.get("type") == "INPUT":
                    act = msg.get("action")
                    with self.lock:
                        ent = self.clients.get(uid)
                        if ent: ent["player"].inbox.append(act)
        except Exception as e:
            log("client error:", e)
        finally:
            try: s.close()
            except Exception: pass
            if uid is not None:
                with self.lock:
                    self.clients.pop(uid, None)

    # ---- helpers ----
    def _compute_result(self):
        results = []
        with self.lock:
            for uid, ent in self.clients.items():
                p: Player = ent["player"]
                results.append({
                    "userId": uid,
                    "score": p.score,
                    "lines": p.lines,
                    "alive": 1 if p.alive else 0,
                    "maxCombo": 0
                })
        # winner / draw
        winner = None; draw = False
        if self.rule == "survival":
            alive_users = [r for r in results if r["alive"]]
            if len(alive_users) == 1:
                winner = alive_users[0]["userId"]
            else:
                draw = True
        else:  # timed / lines（簡化）
            # 以 lines, score 排序
            rs = sorted(results, key=lambda r: (r["lines"], r["score"]), reverse=True)
            if len(rs) >= 2 and rs[0]["lines"] == rs[1]["lines"] and rs[0]["score"] == rs[1]["score"]:
                draw = True
            else:
                winner = rs[0]["userId"]
        return results, winner, draw

    def _report_to_lobby(self, results, winner, draw, reason):
        payload = {
            "type": "MATCH_OVER",
            "serverSecret": self.server_secret,
            "roomId": self.room_id,
            "matchId": self.match_id,
            "rule": self.rule,
            "startAt": int(self.start_ms/1000),
            "endAt": int(time.time()),
            "results": results,
            "winnerUserId": winner,
            "draw": draw,
            "reason": reason,
        }
        try:
            s = socket.create_connection((self.lobby_host, self.lobby_port), timeout=5.0)
            send_json(s, payload)
            ack = recv_json(s)  # 可有可無；若 Lobby 回 OK 會收得到
            log("reported to lobby:", ack)
            s.close()
        except Exception as e:
            log("report lobby failed:", e)

    # ---- game loop ----
    def game_loop(self):
        last_bcast = 0
        drop_ms = self.gravity.get("dropMs", 600)
        while self.running:
            now_ms = int(time.time()*1000)
            with self.lock:
                for uid, ent in list(self.clients.items()):
                    p: Player = ent["player"]
                    if not p.alive: continue
                    p.step_inputs()
                    p.tick_gravity(now_ms, drop_ms)

            if now_ms - last_bcast >= self.broadcast_interval_ms:
                last_bcast = now_ms
                snaps = []
                with self.lock:
                    for uid, ent in list(self.clients.items()):
                        snaps.append(ent["player"].snapshot(now_ms))
                for uid, ent in list(self.clients.items()):
                    try:
                        for snap in snaps:
                            send_json(ent["sock"], snap)
                    except Exception:
                        pass

            reason = None
            if self.rule == "timed":
                if (now_ms - self.start_ms) >= self.match_seconds*1000:
                    reason = "timeup"
            elif self.rule == "survival":
                with self.lock:
                    alive = [ent["player"].alive for ent in self.clients.values()]
                if len(alive) >= 2 and sum(1 for a in alive if a) <= 1:
                    reason = "topout"

            if reason:
                results, winner, draw = self._compute_result()
                # 發給玩家
                payload = {"type":"GAME_OVER","reason":reason,"results":results,"winnerUserId":winner,"draw":draw}
                for uid, ent in list(self.clients.items()):
                    try: send_json(ent["sock"], payload)
                    except Exception: pass
                # 回報 Lobby
                self._report_to_lobby(results, winner, draw, reason)
                self.running = False
                break

            time.sleep(0.016)

def main():
    args = parse_args()
    gs = GameServer(
        args.host, args.port, args.room_id, args.room_token, args.seed, args.rule,
        args.match_id, args.lobby_host, args.lobby_port, args.server_secret
    )
    gs.start()

if __name__ == "__main__":
    main()
