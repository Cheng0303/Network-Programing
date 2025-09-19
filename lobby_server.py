
import argparse
import socketserver
import threading
import sqlite3
import json
import os
import hashlib
import hmac
from datetime import datetime

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_state (
    username TEXT PRIMARY KEY,
    login_count INTEGER NOT NULL DEFAULT 0,
    xp INTEGER NOT NULL DEFAULT 0,
    coins INTEGER NOT NULL DEFAULT 0,
    online INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL DEFAULT ''
);
"""

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

class LobbyDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure()

    def _ensure(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(DB_SCHEMA)
            conn.commit()

    def register(self, username: str, password: str):
        salt = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        pw_hash = hash_password(password, salt)
        created = datetime.utcnow().isoformat()
        with self._lock, sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute("INSERT INTO users(username, password_hash, salt, created_at) VALUES(?,?,?,?)",
                             (username, pw_hash, salt, created))
                conn.execute("INSERT OR IGNORE INTO user_state(username,last_seen) VALUES(?,?)", (username, created))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def verify(self, username: str, password: str) -> bool:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
            row = cur.fetchone()
            if not row:
                return False
            pw_hash, salt = row
            return hmac.compare_digest(pw_hash, hash_password(password, salt))

    def mark_login(self, username: str):
        with self._lock, sqlite3.connect(self.db_path) as conn:
            now = datetime.utcnow().isoformat()
            conn.execute("""
                INSERT INTO user_state(username, login_count, online, last_seen)
                VALUES(?,1,1,?)
                ON CONFLICT(username) DO UPDATE SET
                  login_count = login_count + 1,
                  online = 1,
                  last_seen = excluded.last_seen
            """, (username, now))
            conn.commit()

    def mark_logout(self, username: str):
        with self._lock, sqlite3.connect(self.db_path) as conn:
            now = datetime.utcnow().isoformat()
            conn.execute("""
                UPDATE user_state SET online=0, last_seen=? WHERE username=?
            """, (now, username))
            conn.commit()

    def report(self, username: str, stats: dict):
        # update simple counters (xp, coins)
        with self._lock, sqlite3.connect(self.db_path) as conn:
            now = datetime.utcnow().isoformat()
            xp = int(stats.get("xp", 0))
            coins = int(stats.get("coins", 0))
            conn.execute("""
                INSERT INTO user_state(username, xp, coins, online, last_seen)
                VALUES(?,?,?,1,?)
                ON CONFLICT(username) DO UPDATE SET
                  xp = excluded.xp,
                  coins = excluded.coins,
                  online = 1,
                  last_seen = excluded.last_seen
            """, (username, xp, coins, now))
            conn.commit()

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(60)

        def send(obj):
            data = json.dumps(obj, separators=(",", ":")) + "\n"
            sock.sendall(data.encode("utf-8"))

        def recv_line():
            buf = []
            while True:
                b = sock.recv(1)
                if not b:
                    break
                if b == b"\n":
                    break
                buf.append(b)
            return b"".join(buf).decode("utf-8") if buf else ""

        username_in_session = None

        while True:
            line = recv_line()
            if not line:
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                send({"type":"ERROR","reason":"invalid_json"})
                continue
            t = msg.get("type")
            if t == "REGISTER":
                ok = self.server.db.register(msg.get("username",""), msg.get("password",""))
                send({"type":"REGISTER_OK" if ok else "REGISTER_TAKEN"})
            elif t == "LOGIN":
                u, p = msg.get("username",""), msg.get("password","")
                ok = self.server.db.verify(u, p)
                if ok:
                    self.server.db.mark_login(u)
                    username_in_session = u
                send({"type":"LOGIN_SUCCESS" if ok else "LOGIN_FAIL"})
            elif t == "REPORT":
                u = msg.get("username","")
                stats = msg.get("stats", {})
                self.server.db.report(u, stats)
                send({"type":"REPORT_OK"})
            elif t == "LOGOUT":
                u = msg.get("username","")
                self.server.db.mark_logout(u)
                send({"type":"LOGOUT_OK"})
                break
            elif t == "PLAYERS":
                online = self.server.db.list_online()
                send({"type":"PLAYERS_OK","online": online})
            else:
                send({"type":"ERROR","reason":"unknown_type"})
                break
        # best-effort logout on disconnect
        if username_in_session:
            try:
                self.server.db.mark_logout(username_in_session)
            except Exception:
                pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, server_address, RequestHandlerClass, db: LobbyDB):
        super().__init__(server_address, RequestHandlerClass)
        self.db = db

def main():
    ap = argparse.ArgumentParser(description="Lobby Server (TCP): REGISTER/LOGIN + REPORT/LOGOUT with persistent DB")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=7000)
    ap.add_argument("--db", default="lobby.sqlite")
    args = ap.parse_args()

    db = LobbyDB(args.db)
    srv = ThreadedTCPServer((args.host, args.port), ThreadedTCPRequestHandler, db)
    print(f"[Lobby] Listening on {args.host}:{args.port}, DB={args.db}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[Lobby] Bye.")

if __name__ == "__main__":
    main()
