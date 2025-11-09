import json, struct, socket

_MAX = 65536

def _recvn(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def send_json(sock, obj):
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(data) > _MAX:
        raise ValueError(f"frame too large: {len(data)} > 65536")
    hdr = struct.pack("!I", len(data))
    sock.sendall(hdr); sock.sendall(data)

def recv_json(sock):
    hdr = _recvn(sock, 4)
    (length,) = struct.unpack("!I", hdr)
    if length <= 0 or length > _MAX:
        
        raise ValueError(f"invalid frame length: {length}")
    body = _recvn(sock, length)
    return json.loads(body.decode("utf-8"))
