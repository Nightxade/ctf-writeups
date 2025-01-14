---
layout: writeup
category: UIUCTF-2024
chall_description:
points: 416
solves: 122
tags: UIUCTF-2024 crypto crypto/schnorr-signature crypto/forgery
date: 2024-07-02
comments: false
---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

These signatures are a bore!

`ncat --ssl snore-signatures.chal.uiuc.tf 1337`

[chal.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/snore-chal.py)  

---

Here's the Python source:  

```py
#!/usr/bin/env python3

from Crypto.Util.number import isPrime, getPrime, long_to_bytes, bytes_to_long
from Crypto.Random.random import getrandbits, randint
from Crypto.Hash import SHA512

LOOP_LIMIT = 2000


def hash(val, bits=1024):
    output = 0
    for i in range((bits//512) + 1):
        h = SHA512.new()
        h.update(long_to_bytes(val) + long_to_bytes(i))
        output = int(h.hexdigest(), 16) << (512 * i) ^ output
    return output


def gen_snore_group(N=512):
    q = getPrime(N)
    for _ in range(LOOP_LIMIT):
        X = getrandbits(2*N)
        p = X - X % (2 * q) + 1
        if isPrime(p):
            break
    else:
        raise Exception("Failed to generate group")

    r = (p - 1) // q

    for _ in range(LOOP_LIMIT):
        h = randint(2, p - 1)
        if pow(h, r, p) != 1:
            break
    else:
        raise Exception("Failed to generate group")

    g = pow(h, r, p)

    return (p, q, g)


def snore_gen(p, q, g, N=512):
    x = randint(1, q - 1)
    y = pow(g, -x, p)
    return (x, y)


def snore_sign(p, q, g, x, m):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = hash((r + m) % p) % q
    s = (k + x * e) % q
    return (s, e)


def snore_verify(p, q, g, y, m, s, e):
    if not (0 < s < q):
        return False

    rv = (pow(g, s, p) * pow(y, e, p)) % p
    ev = hash((rv + m) % p) % q

    return ev == e


def main():
    p, q, g = gen_snore_group()
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    queries = []
    for _ in range(10):
        x, y = snore_gen(p, q, g)
        print(f"y = {y}")

        print('you get one query to the oracle')

        m = int(input("m = "))
        queries.append(m)
        s, e = snore_sign(p, q, g, x, m)
        print(f"s = {s}")
        print(f"e = {e}")

        print('can you forge a signature?')
        m = int(input("m = "))
        s = int(input("s = "))
        # you can't change e >:)
        if m in queries:
            print('nope')
            return
        if not snore_verify(p, q, g, y, m, s, e):
            print('invalid signature!')
            return
        queries.append(m)
        print('correct signature!')

    print('you win!')
    print(open('flag.txt').read())

if __name__ == "__main__":
    main()

```

We're provided a very simple signature forgery problem for what seems like a Schnorr signature scheme. First, we are provided `p`, `q`, and `g`, which will remain constant for each query-verification process. At the start of each iteration of the for loop, we are provided `y`. Then, we are allowed one query of any message `m` that we have not used before, and are given the result `s` and `e` from the signature. We are then supposed to submit a message, signature pair of `m` and `s`, such that `m` has not previously been seen by the oracle, such that the pair will produce the same `e`.  

Now, I actually saw people in the discord server mentioning that you can just add multiples of `p` to `m`, which does actually work, since the server considers it different. However, I think my solution was actually the intended.  

Essentially, it all lies in how the signature is verified.  

```py
def snore_verify(p, q, g, y, m, s, e):
    if not (0 < s < q):
        return False

    rv = (pow(g, s, p) * pow(y, e, p)) % p
    ev = hash((rv + m) % p) % q

    return ev == e
```

Remember, we know `p`, `q`, `g`, and `y`, and we control `m` and `s`. Well, what if just increment `s` by 1. Then `rv` will change, but, importantly, since we know all the variables of the expression, we can pretty simply calculate the new value of `rv`. Then, we can subtract the difference between the new and old value of `rv` from `m` (under modulo `p`), since only `rv + m` actually matters in the calculation of `ev`. Thus, our final `ev` will still equal `e`!  

Here's my implementation:  

```py
from pwn import *
from Crypto.Util.number import *

r = remote('snore-signatures.chal.uiuc.tf', 1337, ssl=True)

def rn():
    return int(r.recvline().decode('ascii').split('= ')[-1][:-1])


p = rn()
q = rn()
g = rn()

for i in range(10):

    r.recvuntil(b'y = ').decode('ascii')
    y = rn()

    m = i
    r.sendlineafter(b'm = ', str(m).encode())

    s = rn()
    e = rn()

    o_rv = (pow(g, s, p) * pow(y, e, p)) % p

    s += 1

    n_rv = (pow(g, s, p) * pow(y, e, p)) % p

    n_m = ((o_rv - n_rv) + m) % p

    r.sendlineafter(b'm = ', str(n_m).encode())
    r.sendlineafter(b's = ', str(s).encode())
    

r.interactive()
```

    uiuctf{add1ti0n_i5_n0t_c0nc4t3n4ti0n}