
# HW2 – Online Tetris (MVP fixed, no email)

## Install
python -m pip install -r requirements.txt

## Run (Windows PowerShell)
# A. DB
python -m db_server.main
# B. Lobby
$env:LOBBY_SERVER_SECRET = "dev-secret"
python -m lobby.main --db-host 127.0.0.1 --db-port 11200 --host 127.0.0.1 --port 12000 --public-host 127.0.0.1
# C. Clients (two terminals)
python -m client.cli --lobby 127.0.0.1:12000
