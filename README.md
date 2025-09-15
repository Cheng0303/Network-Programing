
# NP HW1 — Two-Player Online Game (Tic-Tac-Toe with Recycling)

This is a minimal reference implementation in **Python (stdlib only)** that satisfies the assignment requirements:

- **Lobby server (TCP)** with **persistent** account DB (SQLite): register/login
- **Player B** waits on **UDP port >10000** on `linux[1-4].cs.nycu.edu.tw`
- **Player A** scans `linux1..linux4` and a port range for waiting players, **invites via UDP**
- On **ACCEPT**, **Player A hosts TCP** and sends `GAME_TCP{host,port}` to Player B (via UDP)
- Player B connects to A via **TCP** and they play **Tic-Tac-Toe with recycling rule** (see below)
- All game traffic uses **TCP** only

> **Recycling Rule:** Each player can have at most **3 marks** on the board. Starting from the 4th move of a player, after placing the new mark, the **oldest** mark of *that player* is **removed** automatically. Win as soon as you have 3-in-a-row (after recycling is applied).

---

## Files

- `lobby_server.py` — TCP server for REGISTER/LOGIN, persistent SQLite DB
- `player.py` — client: register/login/scan/wait/invite + game host/guest flows
- `protocol.py` — JSON send/recv helpers and board pretty printer
- `game_logic.py` — Tic-Tac-Toe with recycling rule (authoritative on host side)

## How to Run

### 1) Start Lobby (any reachable machine)

```bash
python3 lobby_server.py --host 0.0.0.0 --port 7000 --db lobby.sqlite
```

### 2) Player B (on linux1~linux4)

```bash
# Login or register on lobby (optional for this demo flow, required by HW spec)
python3 player.py --username Bob --lobby linux1.cs.nycu.edu.tw:7000 --password 123 login

# Wait for invitations on a UDP port > 10000
python3 player.py --username Bob wait --udp-port 12001
# (use --auto-accept to accept automatically)
```

### 3) Player A (your laptop / any host)

```bash
# Login
python3 player.py --username Alice --lobby linux1.cs.nycu.edu.tw:7000 --password 123 login

# Scan linux1..linux4 and ports 10001-10020 (change as needed)
python3 player.py --username Alice scan --hosts linux1.cs.nycu.edu.tw,linux2.cs.nycu.edu.tw,linux3.cs.nycu.edu.tw,linux4.cs.nycu.edu.tw --ports 10001-10020

# Invite a discovered B (example target linux2:12001)
python3 player.py --username Alice invite --target linux2.cs.nycu.edu.tw:12001 --tcp-bind-host 0.0.0.0 --tcp-port 5001
```

- After B accepts, A hosts TCP on `--tcp-bind-host:--tcp-port` and sends `GAME_TCP` over UDP.
- B connects via TCP and the game starts.

## Game Controls

Positions are numbered as:

```
 0 1 2
 3 4 5
 6 7 8
```

Enter the cell number on your turn. The host (`Alice`, mark `X`) is authoritative and enforces the recycling rule.

## Protocol Sketch

### Lobby (TCP, JSON lines)

- C → L: `{"type":"REGISTER","username":"alice","password":"p"}`  
  L → C: `{"type":"REGISTER_OK"}` or `{"type":"REGISTER_TAKEN"}`

- C → L: `{"type":"LOGIN","username":"alice","password":"p"}`  
  L → C: `{"type":"LOGIN_SUCCESS"}` or `{"type":"LOGIN_FAIL"}`

### Discovery / Invite (UDP, JSON)

- A → B: `{"type":"DISCOVER","from":"Alice"}`  
  B → A: `{"type":"DISCOVER_ACK","player":"Bob","udp_port":12001}`

- A → B: `{"type":"INVITE","from":"Alice"}`  
  B → A: `{"type":"INVITE_REPLY","decision":"ACCEPT"|"DECLINE"}`

- A (on ACCEPT, after TCP listen) → B: `{"type":"GAME_TCP","host":"A_host","port":5001}`

### Game (TCP, JSON lines)

- A → B: `{"type":"WELCOME","mark":"X","first":"X","rule":"recycle-3"}`
- A ↔ B: `{"type":"YOUR_TURN"}` / `{"type":"MOVE","pos":4}` / `{"type":"STATE","board":"X O ...","turn":"O","recycled":0}`
- A ↔ B: `{"type":"GAME_OVER","winner":"X"|"O"}`

## Notes

- No third-party packages are required.
- Passwords are stored as salted SHA-256 hashes (stdlib). For production, use a stronger KDF.
- A is authoritative in-game to avoid divergence.

## Known Limitations / TODOs

- UDP scanning is sequential (simple). You can add threads to speed up large ranges.
- NAT traversal is out of scope. Provide a reachable `--tcp-bind-host` for B to connect back.
- Minimal error handling; extend as needed for your report.
