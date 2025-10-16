
import json
import socket

ENCODING = "utf-8"

def send_json(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj, separators=(",", ":")) + "\n"
    sock.sendall(data.encode(ENCODING))

def recv_line(sock: socket.socket) -> str:
    buf = []
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        if chunk == b"\n":
            break
        buf.append(chunk)
    return b"".join(buf).decode(ENCODING) if buf else ""

def recv_json(sock: socket.socket):
    line = recv_line(sock)
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"type": "ERROR", "reason": "invalid_json", "raw": line}

def pretty_board(board_str: str) -> str:
    # board_str should be length-9 string of ' ', 'X', 'O'
    s = []
    cells = list(board_str)
    for r in range(3):
        row = " | ".join(c if c != " " else "." for c in cells[r*3:(r+1)*3])
        s.append(" " + row + " ")
        if r < 2:
            s.append("---+---+---")
    return "\n".join(s)
