
import argparse
import socket
import socketserver
import threading
import sqlite3
import json
import os
import hashlib
import hmac
import time
from datetime import datetime

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL
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
            conn.execute(DB_SCHEMA)
            conn.commit()

    def register(self, username: str, password: str):
        salt = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        pw_hash = hash_password(password, salt)
        created = datetime.utcnow().isoformat()
        with self._lock, sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute("INSERT INTO users(username, password_hash, salt, created_at) VALUES(?,?,?,?)",
                             (username, pw_hash, salt, created))
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
                ok = self.server.db.verify(msg.get("username",""), msg.get("password",""))
                send({"type":"LOGIN_SUCCESS" if ok else "LOGIN_FAIL"})
            else:
                send({"type":"ERROR","reason":"unknown_type"})
                break

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, server_address, RequestHandlerClass, db: LobbyDB):
        super().__init__(server_address, RequestHandlerClass)
        self.db = db

def main():
    ap = argparse.ArgumentParser(description="Lobby Server (TCP): REGISTER/LOGIN with persistent DB")
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
