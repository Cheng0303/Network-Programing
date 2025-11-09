
import hashlib, os, time, json, random
from typing import List
def hash_password(pw: str, salt: str = "hw2salt") -> str:
    return hashlib.sha256((salt + pw).encode()).hexdigest()
def gen_token(nbytes: int = 16) -> str:
    return os.urandom(nbytes).hex()
PIECES = ["I","O","T","S","Z","J","L"]
def seven_bag(seed: int):
    rng = random.Random(seed)
    while True:
        b = PIECES[:]; rng.shuffle(b)
        for p in b: yield p
def rle_encode(cells: List[str]) -> str:
    if not cells: return ""
    out=[]; cur=cells[0]; cnt=1
    for x in cells[1:]:
        if x==cur: cnt+=1
        else: out.append(f"{cur}:{cnt}"); cur, cnt = x, 1
    out.append(f"{cur}:{cnt}")
    return ",".join(out)
def rle_decode(s: str) -> List[str]:
    out=[]
    if not s: return out
    for part in s.split(","):
        ch, cnt = part.split(":")
        out.extend([ch]*int(cnt))
    return out
