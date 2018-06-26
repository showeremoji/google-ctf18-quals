from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sys, re
sys.setrecursionlimit(10000)
from pwn import *

# returns g = gcd(a, b), x0, y0, 
# where g = x0*a + y0*b
def xgcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = (a // b, b, a % b)
        x0, x1 = (x1, x0 - q * x1)
        y0, y1 = (y1, y0 - q * y1)
    return (a, x0, y0)


def get_rsadata():
    pubkey = serialization.load_pem_public_key(
            open('key_pub.pem', 'rb').read(), backend=default_backend())
    N = pubkey.public_numbers().n
    e = pubkey.public_numbers().e
    KEY_BYTES = pubkey.key_size // 8
    _, _, inv2 = xgcd(N, 2)
    INV = pow(inv2, e, N)
    return N, KEY_BYTES, INV


def get_cache():
    stored = {}
    try:
        with open('cache', 'r') as f:
            data = f.read().strip().split('\n')
            for l in data:
                n, fn = map(int, l.split())
                stored[n] = fn
    except: pass
    return stored


def int2ascii(v):
    hx = hex(v)[2:].replace('L', '')
    hx = '0' + hx if len(hx)%2 else hx
    return hx.decode('hex')


def enc(v):
    raw = int2ascii(v)
    return '\x00'*(KEY_BYTES - len(raw)) + raw


# gets the last bit of v**d%N from cache or from server.
def lsb_cd(c):
    if c in stored:
        return stored[c]
    back = [0, 0]
    r = remote('perfect-secrecy.ctfcompetition.com', '1337')
    payload = '\x00\x01' + enc(c) # enc - encodes c to ascii and pads with zerobytes.
    r.send(payload)
    data = r.recvn(100)
    r.close()
    for ch in data:
        back[ord(ch)] += 1
    
    ret = 0 if back[0] > back[1] else 1
    stored[c] = ret
    with open('cache', 'a') as f:
        f.write('{} {}\n'.format(c, ret))
    return ret


# returns last k bits of the message m, where c = m**e.
# inv is a number such that 2**e*inv%N == 1
def f(c, k, N, inv):
    if k == 1:
        b = lsb_cd(c) 
        return b
    a = f((c*inv)%N, k-1, N, inv)
    b = lsb_cd(c) 
    if b == 0:
        return 2*a
    else:
        lo = 1<<(k+1)
        return (2*a - N)%lo



if __name__ == '__main__':
    with open('flag.txt', 'rb') as flg:
        asciicipher = flg.read()
        cipher = int(asciicipher.encode('hex'), 16)
    N, KEY_BYTES, INV = get_rsadata()
    stored = get_cache()
    flag = f(cipher, KEY_BYTES*8, N, INV)
    # print flag
    padded = int2ascii(flag)
    m = re.search('CTF\{.+\}', padded)
    print(m.group(0))
