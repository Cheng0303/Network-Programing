# lobby/main.py
import argparse, socket, threading, subprocess, os, time, json, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from common.framing import send_json, recv_json
from common.utils import hash_password, gen_token

DB_HOST, DB_PORT = "127.0.0.1", 11200
HOST, PORT = "0.0.0.0", 12000
PUBLIC_HOST = "127.0.0.1"
SERVER_SECRET = os.getenv("LOBBY_SERVER_SECRET", "dev-secret")

# running_games[roomId] = {"proc": Popen, "port": int, "roomToken": str, "spectateToken": str, "matchId": str}
running_games = {}

SINGLE_SESSION = True
auth_sessions = {}     # conn -> {user, token}
user_sessions = {}     # userId -> conn

# ---------------- DB Client ----------------
class DBClient:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.req_id = 0
    def _rpc(self, coll, action, data):
        self.req_id += 1
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            send_json(s, {"collection": coll, "action": action, "data": data, "reqId": self.req_id})
            resp = recv_json(s)
            if not resp or not resp.get("ok"):
                raise RuntimeError(resp and resp.get("error"))
            return resp.get("data")
    def user_by_name(self, x):
        arr = self._rpc("User", "read", {"filter": {"name": x}})
        return arr[0] if arr else None

# ---------------- helpers ----------------
def _send_to_user_id(user_id, payload):
    for conn, sess in list(auth_sessions.items()):
        try:
            if sess.get("user", {}).get("id") == user_id:
                send_json(conn, payload)
        except Exception:
            pass

def _broadcast_room(room, payload):
    members = room.get("members") or []
    for conn, sess in list(auth_sessions.items()):
        try:
            if sess.get("user", {}).get("id") in members:
                send_json(conn, payload)
        except Exception:
            pass

def _rooms_with_member(dbcli, uid):
    rooms = dbcli._rpc("Room", "read", {"filter": {}})
    return [r for r in rooms if uid in (r.get("members") or [])]

def _user_current_room(dbcli, uid):
    rs = _rooms_with_member(dbcli, uid)
    return rs[0] if rs else None

def _notify_host(room, payload):
    hid = room.get("hostUserId")
    if hid:
        _send_to_user_id(hid, payload)

def _game_path():
    root = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(root, "game_server", "main.py")

def _decorate_room(dbcli, room):
    if not room: return room
    r = dict(room)
    mids = r.get("members") or []
    users = []
    for uid in mids:
        try:
            u = dbcli._rpc("User","read",{"filter":{"id":uid}})
            if u: users.append({"id": u[0].get("id"), "name": u[0].get("name")})
        except Exception: pass
    r["memberUsers"] = users
    try:
        hu = dbcli._rpc("User","read",{"filter":{"id": r.get("hostUserId")}})
        if hu: r["hostName"] = hu[0].get("name")
    except Exception: pass
    return r

def _watch_game(dbcli, room_id, proc):
    proc.wait()
    try:
        dbcli._rpc("Room","update",{"filter":{"id":room_id},"set":{"status":"idle","currentMatchId":None}})
        room = dbcli._rpc("Room","read",{"filter":{"id":room_id}})[0]
        _broadcast_room(_decorate_room(dbcli, room), {"type":"ROOM_UPDATE","room":_decorate_room(dbcli, room)})
    except Exception:
        pass
    finally:
        running_games.pop(room_id, None)

def _close_room_and_notify(dbcli, rid):
    rs = dbcli._rpc("Room","read",{"filter":{"id":rid}})
    if not rs: return
    room = rs[0]
    # 關掉對局進程
    meta = running_games.pop(rid, None)
    if meta and meta.get("proc") and meta["proc"].poll() is None:
        try: meta["proc"].terminate()
        except Exception: pass
    # 通知
    for uid in (room.get("members") or []):
        _send_to_user_id(uid, {"type":"ROOM_CLOSED","roomId": rid})
    # 刪 DB room
    dbcli._rpc("Room","delete",{"filter":{"id":rid}})

# ---------------- per connection ----------------
class ClientThread(threading.Thread):
    def __init__(self, sock, addr, db: DBClient):
        super().__init__(daemon=True)
        self.sock, self.addr, self.db = sock, addr, db
        self.user = None
        self.token = None
        self._cid = None
    def run(self):
        try:
            while True:
                req = recv_json(self.sock)
                if req is None:
                    self._on_disconnect(); return
                try:
                    self._cid = req.get("cid")
                    typ = req.get("type")
                    handler = getattr(self, f"do_{typ}", None)
                    if not handler:
                        self.reply_err("UNKNOWN_COMMAND"); continue
                    handler(req)
                except Exception as e:
                    self.reply_err("SERVER_ERR", detail=str(e))
                finally:
                    self._cid = None
        finally:
            self._on_disconnect()
            try: self.sock.close()
            except Exception: pass

    def reply_ok(self, **kw):
        p = {"type":"OK", **kw}
        if self._cid is not None: p["cid"] = self._cid
        send_json(self.sock, p)
    def reply_err(self, msg, **kw):
        p = {"type":"ERR","msg":msg, **kw}
        if self._cid is not None: p["cid"] = self._cid
        send_json(self.sock, p)
    def require_auth(self):
        if not self.user:
            self.reply_err("NEED_LOGIN"); return False
        return True

    # -------- auth --------
    def do_REGISTER(self, req):
        name = req.get("name"); pw = req.get("password")
        if not (name and pw): return self.reply_err("BAD_ARGS")
        try:
            self.db._rpc("User","create",{"name":name,"email":None,"passwordHash":hash_password(pw)})
            self.reply_ok(msg="REGISTERED")
        except Exception as e:
            self.reply_err("REGISTER_FAIL", detail=str(e))

    def do_LOGIN(self, req):
        x = req.get("name") or req.get("nameOrEmail"); pw = req.get("password")
        if not (x and pw): return self.reply_err("BAD_ARGS")
        u = self.db.user_by_name(x)
        if not u or u.get("passwordHash") != hash_password(pw): return self.reply_err("LOGIN_FAIL")
        # 單一登入
        if SINGLE_SESSION:
            old = user_sessions.get(u["id"])
            if old and old is not self.sock:
                try: send_json(old, {"type":"SESSION_KICK","reason":"duplicate login"})
                except Exception: pass
                try: old.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                try: old.close()
                except Exception: pass
                auth_sessions.pop(old, None)
        # 建 session
        self.user = u; self.token = gen_token()
        auth_sessions[self.sock] = {"user":u,"token":self.token}
        user_sessions[u["id"]] = self.sock
        self.db._rpc("User","update",{"filter":{"id":u["id"]},"set":{"isOnline":1,"lastLoginAt":int(time.time())}})
        self.reply_ok(token=self.token, user=u)

    def do_LOGOUT(self, req):
        if not self.require_auth(): return
        try: self.db._rpc("User","update",{"filter":{"id":self.user["id"]},"set":{"isOnline":0}})
        except Exception: pass
        self.user=None; self.token=None
        self.reply_ok(msg="BYE")

    # -------- listing --------
    def do_LIST_USERS(self, req):
        users = self.db._rpc("User","read",{"filter":{"isOnline":1}})
        self.reply_ok(users=[{"id":u["id"], "name":u["name"]} for u in users])

    def do_LIST_ROOMS(self, req):
        rooms = self.db._rpc("Room","read",{"filter":{"visibility":"public"}})
        decorated = []
        for r in rooms:
            dr = _decorate_room(self.db, r)
            decorated.append({
                "id": dr.get("id"),
                "rule": dr.get("rule") or "timed",
                "members": dr.get("members") or [],
                "memberUsers": dr.get("memberUsers") or [],
                "hostUserId": dr.get("hostUserId"),
                "hostName": dr.get("hostName"),
                "status": dr.get("status"),
            })
        self.reply_ok(rooms=decorated)

    # -------- room lifecycle --------
    def do_CREATE_ROOM(self, req):
        if not self.require_auth(): return
        cur = _user_current_room(self.db, self.user["id"])
        if cur and cur.get("id"): return self.reply_err("ALREADY_IN_ROOM", roomId=cur["id"])
        name = req.get("name") or f"room-{self.user['name']}"
        vis = req.get("visibility") or "public"
        rule = req.get("rule") or "timed"
        r = self.db._rpc("Room","create",{
            "name":name,"hostUserId":self.user["id"],"visibility":vis,
            "members":[self.user["id"]],"inviteList":[],"status":"idle","rule":rule
        })
        room = self.db._rpc("Room","read",{"filter":{"id":r["id"]}})[0]
        send_json(self.sock, {"type":"ROOM_UPDATE","room":_decorate_room(self.db, room)})

    def do_INVITE(self, req):
        if not self.require_auth(): return
        rid = req.get("roomId"); target = req.get("targetUserId")
        room = self._get_room(rid)
        if not room: return self.reply_err("NO_ROOM")
        if self.user["id"] not in (room.get("members") or []): return self.reply_err("NOT_MEMBER")
        inv = set(room.get("inviteList", []))
        inv.add(target)
        self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"inviteList": list(inv)}})
        # 線上才推通知（避免離線反覆彈）
        if target in [u.get("user",{}).get("id") for u in auth_sessions.values()]:
            _send_to_user_id(target, {
                "type":"INVITED","room":_decorate_room(self.db, room),
                "roomId":rid,"hostName":room.get("hostName") or self.user.get("name"),
                "fromUserId": self.user["id"]
            })
        self.reply_ok(msg="INVITED")

    def do_ACCEPT_INVITE(self, req):
        if not self.require_auth(): return
        rid = req.get("roomId"); room = self._get_room(rid)
        if not room: return self.reply_err("NO_ROOM")
        cur = _user_current_room(self.db, self.user["id"])
        if cur and cur.get("id") != rid: return self.reply_err("ALREADY_IN_ROOM", roomId=cur["id"])
        members = list(room.get("members", []))
        if len(members) >= 2: return self.reply_err("ROOM_FULL")
        if self.user["id"] not in members: members.append(self.user["id"])
        inv = [x for x in (room.get("inviteList") or []) if x != self.user["id"]]
        self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"members":members,"inviteList":inv}})
        room = self._get_room(rid)
        _broadcast_room(room, {"type":"ROOM_UPDATE","room":_decorate_room(self.db, room)})
        _notify_host(room, {"type":"ROOM_NOTICE","event":"JOIN","roomId":rid,"userId":self.user["id"]})
        self.reply_ok()

    def do_JOIN_ROOM(self, req):
        if not self.require_auth(): return
        rid = req.get("roomId"); room = self._get_room(rid)
        if not room: return self.reply_err("NO_ROOM")
        cur = _user_current_room(self.db, self.user["id"])
        if cur and cur.get("id") != rid: return self.reply_err("ALREADY_IN_ROOM", roomId=cur["id"])
        if room.get("visibility") != "public": return self.reply_err("NOT_PUBLIC")
        members = list(room.get("members", []))
        if len(members) >= 2: return self.reply_err("ROOM_FULL")
        if self.user["id"] not in members: members.append(self.user["id"])
        self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"members":members}})
        room = self._get_room(rid)
        _broadcast_room(room, {"type":"ROOM_UPDATE","room":_decorate_room(self.db, room)})
        _notify_host(room, {"type":"ROOM_NOTICE","event":"JOIN","roomId":rid,"userId":self.user["id"]})
        self.reply_ok()

    def do_SET_RULE(self, req):
        if not self.require_auth(): return
        rid = req.get("roomId"); new_rule = req.get("rule") or "timed"
        room = self._get_room(rid)
        if not room: return self.reply_err("NO_ROOM")
        if room.get("hostUserId") != self.user["id"]: return self.reply_err("NOT_HOST")
        self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"rule":new_rule}})
        room = self._get_room(rid)
        _broadcast_room(room, {"type":"ROOM_UPDATE","room":_decorate_room(self.db, room)})
        self.reply_ok()

    def do_START_MATCH(self, req):
        if not self.require_auth(): return
        rid = req.get("roomId")
        room = self._get_room(rid)
        if not room: return self.reply_err("NO_ROOM")
        if room.get("hostUserId") != self.user["id"]:
            return self.reply_err("NOT_HOST")
        members = room.get("members", [])
        if len(members) != 2:
            return self.reply_err("NEED_2_PLAYERS")
        if rid in running_games:
            return self.reply_err("MATCH_RUNNING")

        from lobby.port_pool import pick_free_port
        port = pick_free_port()
        token = gen_token(16)
        seed = int(time.time()) & 0x7fffffff
        bag = "7bag"
        gravity = {"mode": "fixed", "dropMs": 600}
        match_id = gen_token(8)
        rule = (room.get("rule") or "timed")

        # 標記 playing
        self.db._rpc("Room", "update", {"filter": {"id": rid}, "set": {"status": "playing", "currentMatchId": match_id}})

        # 啟 GS，記得帶 match-id/lobby/secret
        args = [sys.executable, _game_path(),
                "--host", "0.0.0.0", "--port", str(port),
                "--room-id", str(rid), "--room-token", token,
                "--seed", str(seed), "--rule", rule,
                "--match-id", match_id,
                "--lobby-host", HOST, "--lobby-port", str(PORT),
                "--server-secret", SERVER_SECRET]
        proc = subprocess.Popen(args)
        running_games[rid] = proc
        print(f"[Lobby] GS started pid={proc.pid} room={rid} port={port}")
        threading.Thread(target=_watch_game, args=(self.db, rid, proc), daemon=True).start()

        payload = {"type": "MATCH_READY", "host": PUBLIC_HOST, "port": port, "roomId": rid,
                "roomToken": token, "seed": seed, "bagRule": bag, "rule": rule,
                "gravityPlan": gravity, "matchId": match_id}
        _broadcast_room(room, payload)

    def do_SPECTATE(self, req):
        # 允許「任何已登入的人」觀戰「playing 中」的房間
        if not self.require_auth(): return
        rid = req.get("roomId")
        room = self._get_room(rid)
        if not room: return self.reply_err("INVALID_ROOM")
        if room.get("status") != "playing": return self.reply_err("NOT_PLAYING")
        meta = running_games.get(rid)
        if not meta: return self.reply_err("NO_MATCH_META")
        send_json(self.sock, {
            "type":"SPECTATE_READY",
            "host": PUBLIC_HOST,
            "port": meta["port"],
            "roomId": rid,
            "spectateToken": meta["spectateToken"],
            "matchId": meta["matchId"],
            "rule": room.get("rule") or "timed",
        })

    def do_MATCH_OVER(self, req):
        if req.get("serverSecret") != SERVER_SECRET:
            return self.reply_err("UNAUTHORIZED")

        rid = req.get("roomId")
        match_id = req.get("matchId")
        results = req.get("results", []) or []
        rule = req.get("rule") or "timed"
        startAt = req.get("startAt"); endAt = req.get("endAt")
        winner_uid = req.get("winnerUserId")
        draw = bool(req.get("draw", False))
        reason = req.get("reason")

        room = self._get_room(rid)
        users = room.get("members", []) if room else []

        # 若 GS 未算 winner（且非明確 draw），這邊補一個穩健判定
        if not draw and not winner_uid and results:
            def key_fn(r):
                return (int(r.get("alive", 0)), int(r.get("lines", 0)), int(r.get("score", 0)), int(r.get("maxCombo", 0)))
            winner_uid = max(results, key=key_fn).get("userId")

        # 寫 GameLog（失敗不擋流程）
        try:
            self.db._rpc("GameLog","create",{
                "matchId": match_id, "roomId": rid, "users": users, "rule": rule,
                "startAt": startAt, "endAt": endAt, "results": results
            })
        except Exception:
            pass

        # 房間回 idle
        try:
            self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"status":"idle","currentMatchId":None}})
        except Exception:
            pass

        room2 = self._get_room(rid)
        decorated = _decorate_room(self.db, room2) if room2 else room2

        # 廣播 MATCH_RESULT 給房內成員
        payload = {
            "type": "MATCH_RESULT",
            "roomId": rid,
            "matchId": match_id,
            "rule": rule,
            "winnerUserId": winner_uid,
            "draw": draw,
            "reason": reason,
            "results": results
        }
        if room2:
            _broadcast_room(room2, payload)
            _broadcast_room(room2, {"type":"ROOM_UPDATE","room":decorated})
        else:
            # 房間已不存在，就直接各別通知
            for uid in users: _send_to_user_id(uid, payload)

        self.reply_ok(msg="LOGGED")


    def do_LEAVE_ROOM(self, req):
        if not self.require_auth(): return
        rid = req.get("roomId"); room = self._get_room(rid)
        if not room: return self.reply_err("NO_ROOM")
        uid = self.user["id"]
        if room.get("hostUserId") == uid:
            _close_room_and_notify(self.db, rid)
            return self.reply_ok(msg="ROOM_CLOSED")
        # 成員離開、順便把 inviteList 清掉自己的 id
        newmem = [m for m in (room.get("members") or []) if m != uid]
        newinv = [i for i in (room.get("inviteList") or []) if i != uid]
        self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"members":newmem,"inviteList":newinv}})
        r2 = self._get_room(rid)
        if r2:
            _broadcast_room(r2, {"type":"ROOM_UPDATE","room":_decorate_room(self.db, r2)})
            _notify_host(r2, {"type":"ROOM_NOTICE","event":"LEAVE","roomId":rid,"userId":uid})
        self.reply_ok(msg="LEFT")

    # -------- utils --------
    def _get_room(self, rid):
        rs = self.db._rpc("Room","read",{"filter":{"id":rid}})
        return rs[0] if rs else None

    def _on_disconnect(self):
        if not self.user: return
        uid = self.user["id"]
        # 清 session
        try:
            if user_sessions.get(uid) is self.sock: user_sessions.pop(uid, None)
            auth_sessions.pop(self.sock, None)
        except Exception: pass
        # 標記離線
        try: self.db._rpc("User","update",{"filter":{"id":uid},"set":{"isOnline":0}})
        except Exception: pass
        # 房間清理：把自己從 members / inviteList 剔除；若自己是 host 且沒人了就關房；有其他人則轉移 host
        try:
            rooms = self.db._rpc("Room","read",{"filter":{}})
            for r in rooms:
                mids = list(r.get("members") or [])
                invs = [i for i in (r.get("inviteList") or []) if i != uid]
                if uid not in mids and len(invs) == len(r.get("inviteList") or []):
                    continue
                rid = r["id"]
                if r.get("hostUserId") == uid:
                    others = [m for m in mids if m != uid]
                    if others:
                        self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"members":others,"inviteList":invs,"hostUserId":others[0]}})
                        r2 = self._get_room(rid)
                        if r2: _broadcast_room(r2, {"type":"ROOM_UPDATE","room":_decorate_room(self.db, r2)})
                    else:
                        _close_room_and_notify(self.db, rid)
                else:
                    newmem = [m for m in mids if m != uid]
                    self.db._rpc("Room","update",{"filter":{"id":rid},"set":{"members":newmem,"inviteList":invs}})
                    r2 = self._get_room(rid)
                    if r2:
                        _broadcast_room(r2, {"type":"ROOM_UPDATE","room":_decorate_room(self.db, r2)})
                        _notify_host(r2, {"type":"ROOM_NOTICE","event":"LEAVE","roomId":rid,"userId":uid})
        except Exception: pass
        self.user=None; self.token=None

# ---------------- main ----------------
def main():
    global HOST, PORT, PUBLIC_HOST
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-host", default=DB_HOST)
    ap.add_argument("--db-port", type=int, default=DB_PORT)
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--public-host", default=PUBLIC_HOST)
    args = ap.parse_args()
    HOST, PORT, PUBLIC_HOST = args.host, args.port, args.public_host

    db = DBClient(args.db_host, args.db_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port)); s.listen(128)
    s.settimeout(1.0)
    print(f"[Lobby] {args.host}:{args.port}, DB {args.db_host}:{args.db_port}", flush=True)
    try:
        while True:
            try: c, a = s.accept()
            except socket.timeout: continue
            ClientThread(c, a, db).start()
    except KeyboardInterrupt:
        print("[Lobby] shutting down...", flush=True)
    finally:
        try: s.close()
        except Exception: pass

if __name__ == "__main__":
    main()
