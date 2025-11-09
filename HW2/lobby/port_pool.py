import socket

def pick_free_port(start=15000,end=15999,host='0.0.0.0'):
    for p in range(start,end+1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: s.bind((host,p))
            except OSError: continue
            return p
    raise RuntimeError('no free port in range')
