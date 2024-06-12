---
layout: writeup
category: BCA-CTF-2024
chall_description:
points: 175
solves: 12
tags: crypto ecc invalid-curve-attack
date: 2024-06-12
comments: false
---

Echo is lonely and would like to talk

`nc challs.bcactf.com 31755`

[echo.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/echo.py)  

---

Here's the source code:  

```py
from random import randint
from time import sleep
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def add(p, q):
    if p == (0, 0):
        return q
    if q == (0, 0):
        return p
    if p[0] == q[0] and p[1] != q[1]:
        return (0, 0)
    if p != q:
        l = ((q[1] - p[1]) * pow(q[0] - p[0], -1, n)) % n
    else:
        if p[1] == 0:
            return (0, 0)
        l = ((3 * p[0] * p[0] + a) * pow(2 * p[1], -1, n)) % n
    x = (l * l - p[0] - q[0]) % n
    y = (l * (p[0] - x) - p[1]) % n
    return (x, y)

def mul(k, p):
    q = (0, 0)
    while k > 0:
        if k & 1:
            q = add(q, p)
        p = add(p, p)
        k >>= 1
    return q

priv = randint(1, n - 1)
pub = mul(priv, G)

def enc(m, key=0):
    if key == 0:
        r = randint(1, n - 1)
        R = mul(r, G)
        K = mul(r, pub)
    else:
        R = None
        K = key
    h = SHA256.new()
    h.update(str(K[0]).encode())
    k = h.digest()[:16]
    cipher = AES.new(k, AES.MODE_ECB)
    if R:
        return (R, cipher.encrypt(pad(m, 16)))
    return cipher.encrypt(pad(m, 16))

print("Hi! I'm Echo!")
print("Just a second, I just received a message... give me a bit as I read it...")
print(f"*mumbles* {enc(open("flag.txt", "rb").read())} *mumbles* ah interesting")
while True:
    print("Talk to me! Let's use Diffie-Hellman Key Exchange to stay secure.")
    print("Here is my public key:")
    print(pub)
    print("Please send me a point.")
    x = int(input("x: "))
    y = int(input("y: "))
    rA = (x, y)
    assert rA != (0, 0)
    K = mul(priv, rA)
    print(enc(b"Hey there! Thanks for talking to me :)", K))
    h = input("Want to speak again? (y/n)")
    if h.lower() != "y":
        break


```

This implementation of ECDH (Elliptic Curve Diffie-Hellman Key Exchange) is vulnerable to what is known as an Invalid Curve Attack. [This site](https://github.com/ashutosh1206/Crypton/blob/master/Diffie-Hellman-Key-Exchange/Attack-Invalid-Curve-Point/README.md) explains it great.  

The reason this works is because this server uses a Weierstrass curve, and therefore doesn't utilize a in its point calculations. Additionally, the server does not check if the user-inputted point is on the server's curve.  

Hence, we can use a different curve (specially selected -- read the site linked above about the attack), and the point calculations will calculate a valid point on our chosen curve.  

The one key difference between the solve for this challenge and standard invalid curve attacks is that we cannot take the discrete log of the point the server provides -- instead, we have to brute force the point. Therefore, we have to ensure that the chosen prime factor of the our chosen curve's order is small enough to brute force. `2**20` is definitely small enough, which is why I only used primes less than that. Also, choosing the largest prime possible at each stage allows us to more efficiently determine the private key.  

Besdies that, this is a pretty standard implementation of the invalid curve attack in sage:  

```py
from random import randint
from time import sleep
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
from pwn import *
from tqdm import trange

a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
E = EllipticCurve(GF(n), [a, b])
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def add(p, q):
    if p == (0, 0):
        return q
    if q == (0, 0):
        return p
    if p[0] == q[0] and p[1] != q[1]:
        return (0, 0)
    if p != q:
        l = ((q[1] - p[1]) * pow(q[0] - p[0], -1, n)) % n
    else:
        if p[1] == 0:
            return (0, 0)
        l = ((3 * p[0] * p[0] + a) * pow(2 * p[1], -1, n)) % n
    x = (l * l - p[0] - q[0]) % n
    y = (l * (p[0] - x) - p[1]) % n
    return (x, y)

def mul(k, p):
    q = (0, 0)
    while k > 0:
        if k & 1:
            q = add(q, p)
        p = add(p, p)
        k >>= 1
    return q

def enc(m, key=0):
    if key == 0:
        r = randint(1, n - 1)
        R = mul(r, G)
        K = mul(r, pub)
    else:
        R = None
        K = key
    h = SHA256.new()
    h.update(str(K[0]).encode())
    k = h.digest()[:16]
    cipher = AES.new(k, AES.MODE_ECB)
    if R:
        return (R, cipher.encrypt(pad(m, 16)))
    return cipher.encrypt(pad(m, 16))

p = remote('challs.bcactf.com', '31755')

res = p.recvuntil(b'stay secure.\n').decode('ascii').split('*mumbles* ')[1][:-1]
R, flagct = eval(res)
R = E(R[0], R[1])

p.recvuntil(b'public key:\n')
pub = eval(p.recvline().decode('ascii')[:-1])
pub = E(pub[0], pub[1])

dlogs = []
primes = []
msg = b"Hey there! Thanks for talking to me :)"
tot = 1
while tot < n:
    p.recvrepeat(float(0.1))

    # NOTE: choose curve
    b = randint(1, n)
    E2 = EllipticCurve(GF(n), [a, b])
    order = E2.order()
    print(f'order: {order}')

    # NOTE: choose factor of order
    prime = None
    for i in trange(2**20, 0, -1):
        if order % i == 0:
            if not isPrime(i):
                continue
            prime = i
            break
    if prime != None and prime > 2**10:
        print(f'chose {prime}')

        # NOTE: send point
        P = E2.gen(0)*int(order / prime)
        point = P.xy()
        print(f'point: {point}')
        p.sendline(str(point[0]).encode())
        p.recvrepeat(float(0.1))
        p.sendline(str(point[1]).encode())

        ct = eval(p.recvline().decode('ascii'))
        
        test = P
        for i in trange(2, prime + 1):
            test = test + P
            try:
                K = test.xy()
            except:
                continue
            c = enc(msg, K)
            if c == ct:
                dlogs.append(pow(i, 2, prime))
                primes.append(prime)
                break
    else:
        p.sendline(b'1')
        p.recvrepeat(float(0.1))
        p.sendline(b'1')


    print(dlogs)
    print(primes)

    p.recvrepeat(float(0.1))
    p.sendline(b'y')
    tot = 1
    for _ in primes:
        tot *= _
    print(tot)
    print(n)

priv = CRT_list(dlogs, primes)
print(priv)
print(tot)
print(n)
priv = mod(priv, tot).sqrt(extend=False, all=True)
print(len(priv))
for k in trange(len(priv)):
    K = R*priv[k]
    # print(K)
    h = SHA256.new()
    h.update(str(K.xy()[0]).encode())
    k = h.digest()[:16]
    cipher = AES.new(k, AES.MODE_ECB)
    flag = cipher.decrypt(flagct)
    if b'bcactf' in flag:
        print(flag)
        break
```

    bcactf{3ChO_iS_NOW_8OtH_lOnEly_anD_bR0keN_cdccd6d49c3418}