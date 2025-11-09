# client/gui.py
import argparse, socket, threading, time, sys, os, json, pygame
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from common.framing import send_json, recv_json

# --------- RLE 解析 ---------
def rle_decode_board(rle):
    if not rle: return [[0]*10 for _ in range(20)]
    parts = rle.split(","); vals=[]
    for p in parts:
        if "x" in p:
            v,c = p.split("x"); vals.extend([int(v)]*int(c))
    if len(vals) < 200: vals.extend([0]*(200-len(vals)))
    vals=vals[:200]
    return [vals[i*10:(i+1)*10] for i in range(20)]

# --------- Net ---------
class Net:
    def __init__(self, host, port, room_id, room_token=None, user_id=None, spectate_token=None):
        self.s = socket.create_connection((host, port), timeout=5.0)
        hello = {"type":"HELLO","version":1,"roomId":int(room_id)}
        self.spectator = bool(spectate_token)
        if self.spectator:
            hello["spectateToken"] = str(spectate_token)
        else:
            hello["roomToken"] = str(room_token)
            hello["userId"] = int(user_id)
        send_json(self.s, hello)
        self.welcome = recv_json(self.s)
        if not self.welcome or self.welcome.get("type") != "WELCOME":
            raise RuntimeError(f"bad handshake: {self.welcome}")
        self.s.settimeout(None)
        self.user_id = None if self.spectator else int(user_id)
        self.snap_by_user = {}
        self.running = True
        self.game_over = None
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _recv_loop(self):
        try:
            while self.running:
                msg = recv_json(self.s)
                if not msg: break
                t = msg.get("type")
                if t == "SNAPSHOT":
                    self.snap_by_user[int(msg.get("userId"))] = msg
                elif t == "GAME_OVER":
                    self.game_over = msg
        finally:
            self.running=False
            try: self.s.close()
            except Exception: pass

    def send_input(self, action):
        if self.spectator: return
        try:
            send_json(self.s, {"type":"INPUT","userId":self.user_id,"seq":0,"ts":int(time.time()*1000),"action":action})
        except Exception:
            pass

# --------- Pygame UI ---------
W, H = 960, 560
BG = (20, 22, 27)
FG = (230, 230, 230)
ACCENT = (120, 180, 255)
COLORS = {
    0:(35,37,44),
    1:(0,255,255), 2:(255,255,0), 3:(160,0,240),
    4:(0,255,0),   5:(255,0,0),   6:(0,0,255), 7:(255,165,0),
}

def draw_text(surf, text, x, y, size=22, color=FG):
    font = pygame.font.SysFont("consolas", size)
    surf.blit(font.render(text, True, color), (x, y))

def draw_board(surf, board, ox, oy, cell=20, active=None):
    pygame.draw.rect(surf, (30,32,38), (ox-2, oy-2, 10*cell+4, 20*cell+4), border_radius=6)
    for y in range(20):
        for x in range(10):
            v = board[y][x]
            pygame.draw.rect(surf, COLORS.get(v,(80,80,80)), (ox+x*cell, oy+y*cell, cell-1, cell-1))
    if active and active.get("shape"):
        shapes = {
            "I":[[(0,1),(1,1),(2,1),(3,1)],[(2,0),(2,1),(2,2),(2,3)],[(0,2),(1,2),(2,2),(3,2)],[(1,0),(1,1),(1,2),(1,3)]],
            "O":[[(1,0),(2,0),(1,1),(2,1)]]*4,
            "T":[[(1,0),(0,1),(1,1),(2,1)],[(1,0),(1,1),(2,1),(1,2)],[(0,1),(1,1),(2,1),(1,2)],[(1,0),(0,1),(1,1),(1,2)]],
            "S":[[(1,0),(2,0),(0,1),(1,1)],[(1,0),(1,1),(2,1),(2,2)],[(1,1),(2,1),(0,2),(1,2)],[(0,0),(0,1),(1,1),(1,2)]],
            "Z":[[(0,0),(1,0),(1,1),(2,1)],[(2,0),(1,1),(2,1),(1,2)],[(0,1),(1,1),(1,2),(2,2)],[(1,0),(0,1),(1,1),(0,2)]],
            "J":[[(0,0),(0,1),(1,1),(2,1)],[(1,0),(2,0),(1,1),(1,2)],[(0,1),(1,1),(2,1),(2,2)],[(1,0),(1,1),(0,2),(1,2)]],
            "L":[[(2,0),(0,1),(1,1),(2,1)],[(1,0),(1,1),(1,2),(2,2)],[(0,1),(1,1),(2,1),(0,2)],[(0,0),(1,0),(1,1),(1,2)]],
        }
        code = {"I":1,"O":2,"T":3,"S":4,"Z":5,"J":6,"L":7}[active["shape"]]
        ax, ay, rot = active.get("x",0), active.get("y",0), active.get("rot",0)
        for (dx,dy) in shapes[active["shape"]][rot%4]:
            x = ax+dx; y = ay+dy
            if y >= 0:
                pygame.draw.rect(surf, COLORS.get(code,(220,220,220)), (ox+x*cell, oy+y*cell, cell-1, cell-1))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--room-id", type=int, required=True)
    ap.add_argument("--room-token")
    ap.add_argument("--user-id", type=int)
    ap.add_argument("--spectate-token")
    args = ap.parse_args()

    pygame.init()
    screen = pygame.display.set_mode((W, H))
    pygame.display.set_caption("HW2 Tetris")
    clock = pygame.time.Clock()

    try:
        net = Net(args.host, args.port, args.room_id,
                  room_token=args.room_token, user_id=args.user_id,
                  spectate_token=args.spectate_token)
    except Exception as e:
        screen.fill(BG); draw_text(screen, f"Handshake failed: {e}", 20, 20, 22, (255,120,120)); pygame.display.flip(); time.sleep(3.0); return

    spectator = bool(args.spectate_token)

    while True:
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT: return
            elif ev.type == pygame.KEYDOWN:
                if ev.key == pygame.K_ESCAPE: return
                if not spectator:
                    if ev.key == pygame.K_LEFT:  net.send_input("L")
                    if ev.key == pygame.K_RIGHT: net.send_input("R")
                    if ev.key == pygame.K_UP:    net.send_input("CW")
                    if ev.key == pygame.K_z:     net.send_input("CCW")
                    if ev.key == pygame.K_DOWN:  net.send_input("SD")
                    if ev.key == pygame.K_SPACE: net.send_input("HD")
                    if ev.key == pygame.K_c:     net.send_input("HOLD")

        screen.fill(BG)
        hdr = f"{'SPECTATE' if spectator else 'PLAY'}  room={args.room_id}  rule={net.welcome.get('rule')}  match={net.welcome.get('matchId','-')}"
        draw_text(screen, hdr, 20, 16, 22, ACCENT)

        # 收集兩個玩家的快照（若不足兩個就顯示現有的）
        snaps = list(sorted(net.snap_by_user.values(), key=lambda s: s.get("userId")))
        if spectator:
            # 左右並排
            if len(snaps) >= 1:
                s1 = snaps[0]; b1 = rle_decode_board(s1.get("boardRLE"))
                draw_text(screen, f"P1 uid={s1.get('userId')}  score={s1.get('score',0)}  lines={s1.get('lines',0)}", 20, 48)
                draw_board(screen, b1, 20, 80, cell=20, active=s1.get("active"))
            if len(snaps) >= 2:
                s2 = snaps[1]; b2 = rle_decode_board(s2.get("boardRLE"))
                draw_text(screen, f"P2 uid={s2.get('userId')}  score={s2.get('score',0)}  lines={s2.get('lines',0)}", 520, 48)
                draw_board(screen, b2, 520, 80, cell=20, active=s2.get("active"))
        else:
            my = net.snap_by_user.get(net.user_id)
            opp = None
            for snap in snaps:
                if snap.get("userId") != net.user_id:
                    opp = snap; break
            if my:
                b = rle_decode_board(my.get("boardRLE"))
                draw_text(screen, f"YOU uid={my.get('userId')}  score={my.get('score',0)}  lines={my.get('lines',0)}", 20, 48)
                draw_board(screen, b, 20, 80, cell=22, active=my.get("active"))
            else:
                draw_text(screen, "Waiting for your snapshot...", 20, 48)
            if opp:
                b2 = rle_decode_board(opp.get("boardRLE"))
                draw_text(screen, f"OPP uid={opp.get('userId')}  score={opp.get('score',0)}  lines={opp.get('lines',0)}", 560, 48)
                draw_board(screen, b2, 560, 80, cell=16, active=opp.get("active"))

        if net.game_over:
            draw_text(screen, f"GAME OVER: {net.game_over.get('reason')}", 20, 520, 24, (255,120,120))

        pygame.display.flip()
        clock.tick(60)

if __name__ == "__main__":
    main()
