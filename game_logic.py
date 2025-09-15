
from collections import deque

WIN_LINES = [
    (0,1,2),(3,4,5),(6,7,8),
    (0,3,6),(1,4,7),(2,5,8),
    (0,4,8),(2,4,6)
]

class TicTacToeRecycling:
    def __init__(self):
        self.board = [" "] * 9
        self.turn = "X"
        self.history = {"X": deque(), "O": deque()}

    def reset(self, first="X"):
        self.board = [" "] * 9
        self.turn = first
        self.history = {"X": deque(), "O": deque()}

    def is_legal(self, pos: int) -> bool:
        return 0 <= pos < 9 and self.board[pos] == " "

    def apply_move(self, player: str, pos: int):
        if player != self.turn:
            return False, {"reason": "not_your_turn"}
        if not self.is_legal(pos):
            return False, {"reason": "illegal_cell"}
       
        self.board[pos] = player
        self.history[player].append(pos)
        recycled = None
       
        if len(self.history[player]) > 3:
            oldest = self.history[player].popleft()
            
            if oldest != pos and self.board[oldest] == player:
                self.board[oldest] = " "
                recycled = oldest
        
        winner = self._winner_for(player)
        
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

    @staticmethod
    def render_board_str(board_str: str) -> str:
        cells = list(board_str)
        out = []
        for r in range(3):
            out.append(" " + " | ".join(c if c != " " else "." for c in cells[r*3:(r+1)*3]) + " ")
            if r < 2:
                out.append("---+---+---")
        return "\n".join(out)
