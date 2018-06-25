# DM collision

The challenge used a Davies-Meyer one-way compression function, with a modified version of DES as block cipher.

The goal of this challenge was twofold:

1. Find any collision in the one-way compression function, and
2. Find a pre-image attack such that the output of the compression function is all zeros.

The challenge is solved if we successfully send three pairs of input to a server:

(b1key, b1input)
(b2key, b2input)
(b3key, b3input)

Such that Comp(b1key, b1input) == Comp(b2key, b2input) and Comp(b3key, b3input) == 0.

## DES modifications

The `not_des.py` file contains something that is extremely similar to DES. Upon closer inspection, we see that it is exactly DES, but with the order of the S-boxes changed. 

SBOXES = [S6, S4, S1, S5, S3, S2, S8, S7]

where the original DES would have the S-boxes in regular ascending order from 1 to 8.

## Part 1 - Finding any collision

We first note that (b1key, b1input) must be distinct from (b2key, b2input), so we cannot simple use duplicated input to get a collision.

However, getting a collision is simple, since DES takes 64 bit as key, but internally only uses 56 bits.
This means that we can simply send in two very similar keys, but with only one bit difference.
The server implementation will consider this as two different keys, but the DES-implementation will internally generate the same key schedule since the differing bit is discarded anyway.

Thus we can use `(abcdefgh, aaaaaaaa)` and `(abcdefgi, aaaaaaaa)` as the two first inputs.

## Part 2 - Find a pre-image

For this part, we need to utilise the fact that in the Davies-Meyer construction, we get:

`output = Comp(k, m) = E_k(m) XOR m`

which we want to be zero. Thus we want to find a fixed point of the encryption function E (which is DES),
such that `E_k(m) = m`.

Finding such points is hard in the general case, however, we note that DES has a small subset of keys that are called _weak keys_.  Indeed, it turns out that for such a weak key, the number of fixed points are large, namely 2<sup>32</sup>.
For a proof, see e.g [1].

An example of such a weak key is: `{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01}`.

We can now brute-force over the message space, knowing that we reasonably fast (order of 2<sup>32</sup>) will find a fixed point. However, DES is a fairly slow block cipher in software, so the given Python implementation is too slow.
Instead, I modified an existing DES implementation [2] to use the modified order of the S-boxes.
This, combined with a randomized starting position of the message, and multiple parallell instances of the application gave the following fixed point:

`454b9b579f15d67f -> 454b9b579f15d67f`

Thus, submitting the above mentioned weak key together with the above message results in getting the all zero output, and the script returns the following flag:

`CTF{7h3r35 4 f1r3 574r71n6 1n my h34r7 r34ch1n6 4 f3v3r p17ch 4nd 175 br1n61n6 m3 0u7 7h3 d4rk}`

## References

[1] Coppersmith D. (1986) _The Real Reason for Rivest’s Phenomenon_. (Advances in Cryptology -- CRYPTO '85 Proceedings. CRYPTO 1985)

[2] https://github.com/B-Con/crypto-algorithms
