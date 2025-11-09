import socket, threading, sqlite3, json, time, sys, os, argparse

# 讓 "from common.framing import ..." 可用
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from common.framing import send_json, recv_json

# ===== Config =====
DB_PATH_DEFAULT = "hw2.sqlite3"

# ===== Schema =====
SCHEMA = {
    "User": '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            email TEXT,
            passwordHash TEXT,
            createdAt INTEGER,
            lastLoginAt INTEGER,
            isOnline INTEGER DEFAULT 0
        );
    ''',
    "Room": '''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            hostUserId INTEGER,
            visibility TEXT,
            inviteList TEXT,      -- JSON array
            status TEXT,
            members TEXT,         -- JSON array
            createdAt INTEGER,
            currentMatchId TEXT,
            rule TEXT
        );
    ''',
    "GameLog": '''
        CREATE TABLE IF NOT EXISTS gamelogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            matchId TEXT,
            roomId INTEGER,
            users TEXT,           -- JSON array
            rule TEXT,
            startAt INTEGER,
            endAt INTEGER,
            results TEXT          -- JSON array
        );
    ''',
}

# ===== Helpers =====
def _now() -> int:
    return int(time.time())

def _dump(x):
    return json.dumps(x, separators=(",", ":")) if x is not None else None

def _load(s, default=None):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

def _table_cols(conn, table):
    cur = conn.cursor()
    rows = cur.execute(f"PRAGMA table_info('{table}')").fetchall()
    return [r[1] for r in rows]

# ===== DB Layer =====
class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        cur = self.conn.cursor()
        for sql in SCHEMA.values():
            cur.execute(sql)
        # 容錯：確保 rooms 有 rule 欄位
        cols = [r[1] for r in cur.execute("PRAGMA table_info('rooms')").fetchall()]
        if "rule" not in cols:
            cur.execute("ALTER TABLE rooms ADD COLUMN rule TEXT")
        self.conn.commit()

    def create(self, coll, doc):
        if coll == "User":
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO users(name,email,passwordHash,createdAt,lastLoginAt,isOnline) VALUES(?,?,?,?,?,?)",
                (doc.get("name"), doc.get("email"), doc.get("passwordHash"),
                 _now(), None, 0)
            )
            self.conn.commit()
            return {"id": cur.lastrowid}

        if coll == "Room":
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO rooms(name,hostUserId,visibility,inviteList,status,members,createdAt,currentMatchId,rule)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (doc.get("name"),
                 doc.get("hostUserId"),
                 doc.get("visibility", "public"),
                 _dump(doc.get("inviteList", [])),
                 doc.get("status", "idle"),
                 _dump(doc.get("members", [])),
                 _now(),
                 None,
                 doc.get("rule", "timed"))
            )
            self.conn.commit()
            return {"id": cur.lastrowid}

        if coll == "GameLog":
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO gamelogs(matchId,roomId,users,rule,startAt,endAt,results) VALUES(?,?,?,?,?,?,?)",
                (doc.get("matchId"),
                 doc.get("roomId"),
                 _dump(doc.get("users", [])),
                 doc.get("rule"),
                 doc.get("startAt"),
                 doc.get("endAt"),
                 _dump(doc.get("results", [])))
            )
            self.conn.commit()
            return {"id": cur.lastrowid}

        raise ValueError("unknown collection")

    def read(self, coll, flt):
        cur = self.conn.cursor()
        table = {"User": "users", "Room": "rooms", "GameLog": "gamelogs"}[coll]
        q = f"SELECT * FROM {table}"
        args = []
        if flt:
            conds = []
            for k, v in flt.items():
                conds.append(f"{k}=?")
                args.append(v)
            if conds:
                q += " WHERE " + " AND ".join(conds)
        rows = cur.execute(q, args).fetchall()

        if coll == "User":
            return [dict(r) for r in rows]

        if coll == "Room":
            out = []
            for r in rows:
                d = dict(r)
                d["inviteList"] = _load(d.get("inviteList"), [])
                d["members"] = _load(d.get("members"), [])
                out.append(d)
            return out

        if coll == "GameLog":
            out = []
            for r in rows:
                d = dict(r)
                d["users"] = _load(d.get("users"), [])
                d["results"] = _load(d.get("results"), [])
                out.append(d)
            return out

        return []

    def update(self, coll, flt, setobj):
        cur = self.conn.cursor()
        table = {"User": "users", "Room": "rooms", "GameLog": "gamelogs"}[coll]
        valid_cols = set(_table_cols(self.conn, table))

        set_parts, set_args = [], []
        for k, v in (setobj or {}).items():
            if k not in valid_cols:
                continue
            if k in ("inviteList", "members", "users", "results"):
                v = _dump(v)
            set_parts.append(f"{k}=?")
            set_args.append(v)

        if not set_parts:
            return {"updated": 0}

        where_parts, where_args = [], []
        if flt:
            for k, v in flt.items():
                where_parts.append(f"{k}=?")
                where_args.append(v)

        q = f"UPDATE {table} SET " + ", ".join(set_parts)
        if where_parts:
            q += " WHERE " + " AND ".join(where_parts)

        args = set_args + where_args
        cur.execute(q, args)
        self.conn.commit()
        return {"updated": cur.rowcount}

    def delete(self, coll, flt):
        cur = self.conn.cursor()
        table = {"User": "users", "Room": "rooms", "GameLog": "gamelogs"}[coll]
        where_parts, where_args = [], []
        if flt:
            for k, v in flt.items():
                where_parts.append(f"{k}=?"); where_args.append(v)
        q = f"DELETE FROM {table}"
        if where_parts:
            q += " WHERE " + " AND ".join(where_parts)
        cur.execute(q, where_args)
        self.conn.commit()
        return {"deleted": cur.rowcount}

# ===== Per-connection handler =====
class ClientThread(threading.Thread):
    def __init__(self, sock, addr, db: DB):
        super().__init__(daemon=True)
        self.sock, self.addr, self.db = sock, addr, db

    def run(self):
        try:
            while True:
                req = recv_json(self.sock)
                if req is None:
                    return
                try:
                    resp = self.handle(req)
                    resp["ok"] = True
                except Exception as e:
                    resp = {"ok": False, "error": {"code": "DB_ERROR", "msg": str(e)}}
                resp["reqId"] = req.get("reqId")
                send_json(self.sock, resp)
        finally:
            try: self.sock.close()
            except Exception: pass

    def handle(self, req):
        coll = req.get("collection")
        action = req.get("action")
        data = req.get("data", {}) or {}

        if action == "create":
            return {"data": self.db.create(coll, data)}
        if action == "read":
            return {"data": self.db.read(coll, data.get("filter"))}
        if action == "update":
            return {"data": self.db.update(coll, data.get("filter"), data.get("set", {}))}
        if action == "delete":
            return {"data": self.db.delete(coll, data.get("filter"))}
        if action == "query":   # alias to read
            return {"data": self.db.read(coll, data.get("filter"))}

        raise ValueError("unknown action")

# ===== Server main =====
def parse_args():
    ap = argparse.ArgumentParser(description="HW2 DB Server (TCP + JSON over length-prefixed framing)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=11200)
    ap.add_argument("--db",   default=DB_PATH_DEFAULT, help="SQLite file path")
    return ap.parse_args()

def main():
    args = parse_args()
    db = DB(args.db)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen(128)
    s.settimeout(1.0)  # 讓 Ctrl+C 更好用
    print(f"[DB] listening on {args.host}:{args.port} (db={args.db})", flush=True)

    try:
        while True:
            try:
                c, a = s.accept()
            except socket.timeout:
                continue
            ClientThread(c, a, db).start()
    except KeyboardInterrupt:
        print("\n[DB] shutting down...", flush=True)
    finally:
        try: s.close()
        except Exception: pass

if __name__ == "__main__":
    main()
