# Perfect Secrecy
We are given a ciphertext `c` in `flag.txt`, a public key with `N` and `e` in `key_pub.pem`.

We can also send a cipher to a server, and it will send back some zero and one-bytes.

The goal is to find `m` such that `m**e % N == c`, i.e., finding the RSA-message.

Inspecting `challenge.py` - what the server does.

It receives two bytes `m0` and `m1`. Then it decrypts (raises to the power of the secret value `d` mod `N`) the next key-size bits we send, and stores it in the variable `dice`.

Then follows this suspiciously looking code:

```python
for rounds in range(100):
  p = [m0, m1][dice & 1]
  k = random.randint(0, 2)
  c = (ord(p) + k) % 2
  writer.write(bytes((c,)))
```

`random.randint(a, b)` generates a uniformly random rumber in the range `[a, b]`, mening that we have probablility `1/3` for each outcome of `k` being `0`, `1` or `2`. `c` will therefore with probability `2/3` be `ord(p)%2`, and with probability `1/3` be `(ord(p)+1)%2`. We therefore expect about 67 of the bytes to be `ord(p)` and 33 to be the other.

We can either calculate the probability of receiving more `(ord(p)+1)%2`-bytes of the `100` bytes sent to us. Or we can experimentally check what we get by letting the server decrypt `1`, which we know will become `1`, and verify that we always get more `m1` than `m0` back, if we let `m0, m1 = '\x00', '\x01'`.

We can hence get the lsb of `c**d` for any `c` by asking the server - we call this function `lsb_cd(c)`. 

```python 
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
```

We implemented a simple caching of the results, since the server responded very slowly.

## Reconstructing `m`

So we get the last bit of `m` by sending `c` to the server. Then we'd like to send a `c'` corresponding to `m>>1` to find the next bit. However, this `c'` is not so easy to find. What we can do is to muliply `c` with `inv(2)**e`, which is the `c''` corresponding to `m*inv(2)`. This is `m>>1` if `m` is even, however if `m` is odd, `m*inv(2) = (m+N)>>1`, but this is possible to find `m>>1` by subtracting `N`.

The inverse of `2` mod `N` can be found by the extended euclidean algorithm, given that `gcd(2, N) == 1`, which is true when `N` is used for RSA encryption. 

Consider a function `f(c, k)` that reconstructs the last `k` bits of `c**d`. 

Clearly `f(c, 1) = lsb_cd(c)`. 

If `lsb_cd(c) == 0`, then `f(c, k) = 2 * f(c*inv(2)**e, k-1)`, otherwise `f(c, k) + N%(2**(k+1)) = 2*f(c*inv(2)**e, k-1)`. 

This can be implemented in python in the followig way:

```python
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
```

`m = f(c, key_size, N, inv(2)**e%N)`.

Anfter about an hour of `1024` requests to the server and soem restarts,

## Extracting the flag 
can be done by converting the int to ascii, easiest done going via hex:

```python
def int2ascii(v):
    hx = hex(v)[2:].replace('L', '')
    hx = '0' + hx if len(hx)%2 else hx
    return hx.decode('hex')
```

It turns out that the flag is padded with random bytes, but with those thrown away it's an Adele reference:

`CTF{h3ll0__17_5_m3_1_w45_w0nd3r1n6_1f_4f73r_4ll_7h353_y34r5_y0u_d_l1k3_70_m337}`
