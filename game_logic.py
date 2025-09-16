
from collections import deque

WIN_LINES = [
    (0,1,2),(3,4,5),(6,7,8),
    (0,3,6),(1,4,7),(2,5,8),
    (0,4,8),(2,4,6)
]

class TicTacToeRecycling:
    """
    Tic-Tac-Toe with recycling rule:
    - Each player can have at most 3 marks on the board.
    - On a player's 4th (and subsequent) move, after placing the new mark,
      the oldest mark that *this player* placed is automatically removed.
    - Win condition: after your move (including recycling), if you have 3-in-a-row, you win.
    """
    def __init__(self):
        self.board = [" "] * 9
        self.turn = "X"  # 'X' starts by default
        self.history = {"X": deque(), "O": deque()}  # stores cell indices in order for each player

    def reset(self, first="X"):
        self.board = [" "] * 9
        self.turn = first
        self.history = {"X": deque(), "O": deque()}

    def is_legal(self, pos: int) -> bool:
        return 0 <= pos < 9 and self.board[pos] == " "

    def apply_move(self, player: str, pos: int):
        """Returns (ok: bool, info: dict). info may contain keys: recycled, winner"""
        if player != self.turn:
            return False, {"reason": "not_your_turn"}
        if not self.is_legal(pos):
            return False, {"reason": "illegal_cell"}
        # place
        self.board[pos] = player
        self.history[player].append(pos)
        recycled = None
        # recycle oldest if > 3
        if len(self.history[player]) > 3:
            oldest = self.history[player].popleft()
            if oldest != pos and self.board[oldest] == player:
                self.board[oldest] = " "
                recycled = oldest
        # check win after recycling
        winner = self._winner_for(player)
        # next turn
        self.turn = "O" if self.turn == "X" else "X"
        info = {"winner": winner, "recycled": recycled}
        return True, info

    def _winner_for(self, player: str):
        for a,b,c in WIN_LINES:
            if self.board[a] == self.board[b] == self.board[c] == player:
                return player
        return None

    def board_str(self) -> str:
        return "".join(self.board)
