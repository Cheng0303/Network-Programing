#!/usr/bin/env python3
import argparse
import socketserver
import threading
import sqlite3
import json
import os
import hashlib
import hmac
from datetime import datetime, timezone, timedelta

from protocol import send_json, recv_json  # 你現有的 line-delimited JSON 協定

UTC = timezone.utc

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_state (
    username TEXT PRIMARY KEY,
    online INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL,
    login_count INTEGER NOT NULL DEFAULT 0,
    xp INTEGER NOT NULL DEFAULT 0,
    coins INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
"""

def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()

def hash_password(password: str, salt: str) -> str:
    # 穩定簡單的雜湊（課內作業足夠；正式系統請改為 bcrypt/scrypt/argon2）
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

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
        created = utc_now_iso()
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT 1 FROM users WHERE username=?", (username,))
            if cur.fetchone():
                return False, "username_taken"
            conn.execute(
                "INSERT INTO users(username,password_hash,salt,created_at) VALUES(?,?,?,?)",
                (username, pw_hash, salt, created),
            )
            conn.execute(
                "INSERT INTO user_state(username,online,last_seen,login_count,xp,coins) VALUES(?,?,?,?,?,?)",
                (username, 0, created, 0, 0, 0),
            )
            conn.commit()
        return True, "ok"

    def verify(self, username: str, password: str) -> bool:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
            row = cur.fetchone()
            if not row:
                return False
            ph, salt = row
            return hmac.compare_digest(ph, hash_password(password, salt))

    def _get_state(self, conn, username: str):
        cur = conn.execute("SELECT online,last_seen,login_count,xp,coins FROM user_state WHERE username=?", (username,))
        return cur.fetchone()

    def is_online(self, username: str, stale_sec: int) -> bool:
        """True iff online 且 last_seen 未過期。若過期自動清成離線。"""
        with self._lock, sqlite3.connect(self.db_path) as conn:
            row = self._get_state(conn, username)
            if not row:
                return False
            online, last_seen, *_ = row
            if int(online) == 0:
                return False
            try:
                last_dt = datetime.fromisoformat(last_seen)
            except Exception:
                last_dt = datetime.now(UTC) - timedelta(days=365*10)
            if (datetime.now(UTC) - last_dt).total_seconds() > stale_sec:
                conn.execute("UPDATE user_state SET online=0 WHERE username=?", (username,))
                conn.commit()
                return False
            return True

    def mark_login(self, username: str):
        now = utc_now_iso()
        with self._lock, sqlite3.connect(self.db_path) as conn:
            row = self._get_state(conn, username)
            if not row:
                return None
            online, last_seen, login_count, xp, coins = row
            login_count = int(login_count) + 1
            conn.execute(
                "UPDATE user_state SET online=1,last_seen=?,login_count=? WHERE username=?",
                (now, login_count, username),
            )
            conn.commit()
            return {"login_count": login_count, "xp": int(xp), "coins": int(coins)}

    def mark_logout(self, username: str):
        now = utc_now_iso()
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE user_state SET online=0,last_seen=? WHERE username=?", (now, username))
            conn.commit()

    def update_seen(self, username: str):
        now = utc_now_iso()
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE user_state SET last_seen=? WHERE username=?", (now, username))
            conn.commit()

    def profile(self, username: str):
        with self._lock, sqlite3.connect(self.db_path) as conn:
            row = self._get_state(conn, username)
            if not row: return None
            online, last_seen, login_count, xp, coins = row
            return {
                "online": int(online),
                "last_seen": last_seen,
                "login_count": int(login_count),
                "xp": int(xp),
                "coins": int(coins),
            }

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # 單請求/連線：讀一個 JSON，回一個 JSON，然後由 client 關閉
        server = self.server  # type: ignore
        verbose = getattr(server, "verbose", False)
        stale_sec = getattr(server, "stale_sec", 30)

        try:
            msg = recv_json(self.request)
        except Exception:
            return

        if not isinstance(msg, dict):
            send_json(self.request, {"type":"ERROR","reason":"bad_request"})
            return

        t = msg.get("type")
        if verbose:
            print(f"[Lobby] {self.client_address} -> {t}: {msg}")

        # --- 指令處理 ---
        if t == "PING":
            send_json(self.request, {"type":"PONG","ts":utc_now_iso()})
            return

        if t == "REGISTER":
            u, p = msg.get("username",""), msg.get("password","")
            if not u or not p:
                send_json(self.request, {"type":"REGISTER_FAIL","reason":"missing_fields"})
                return
            ok, why = server.db.register(u, p)
            if ok:
                send_json(self.request, {"type":"REGISTER_OK"})
            else:
                send_json(self.request, {"type":"REGISTER_FAIL","reason":why})
            return

        if t == "LOGIN":
            u, p = msg.get("username",""), msg.get("password","")
            if not server.db.verify(u, p):
                send_json(self.request, {"type":"LOGIN_FAIL","reason":"bad_credentials"})
                return
            # 直接在登入時阻擋重登（含 stale 檢查）
            if server.db.is_online(u, stale_sec=stale_sec):
                send_json(self.request, {"type":"LOGIN_DUPLICATE"})
                return
            prof = server.db.mark_login(u)
            send_json(self.request, {"type":"LOGIN_SUCCESS","profile":prof})
            return

        if t == "LOGOUT":
            u = msg.get("username","")
            server.db.mark_logout(u)
            send_json(self.request, {"type":"LOGOUT_OK"})
            return

        if t == "REPORT":
            # 心跳用來維持 last_seen，避免被視為離線
            u = msg.get("username","")
            if not u:
                send_json(self.request, {"type":"ERROR","reason":"missing_username"})
                return
            server.db.update_seen(u)
            send_json(self.request, {"type":"REPORT_OK"})
            return

        if t == "PROFILE":
            u = msg.get("username","")
            prof = server.db.profile(u)
            if prof is None:
                send_json(self.request, {"type":"ERROR","reason":"no_such_user"})
            else:
                send_json(self.request, {"type":"PROFILE","profile":prof})
            return

        send_json(self.request, {"type":"ERROR","reason":"unknown_type"})

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, db: LobbyDB):
        super().__init__(server_address, RequestHandlerClass)
        self.db = db
        self.verbose = False
        self.stale_sec = 30  # 可由 CLI 覆蓋

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=7000)
    ap.add_argument("--db", default="lobby.db")
    ap.add_argument("--stale-sec", type=int, default=300, help="秒數；超過視為離線（擋重登會先清除 staleness）")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    db = LobbyDB(args.db)
    srv = ThreadedTCPServer((args.host, args.port), ThreadedTCPRequestHandler, db)
    srv.verbose = args.verbose
    srv.stale_sec = args.stale_sec
    print(f"[Lobby] Listening on {args.host}:{args.port}, DB={args.db}, stale={args.stale_sec}s")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[Lobby] Bye.")

if __name__ == "__main__":
    main()
