---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/7OCvijy.png
points: 349
solves: 102
tags: crypto crypto/rsa crypto/broken-rsa
date: 2023-12-4
comments: false
---

Exponents took too long. I decided to use an alternative. It won't about the same right? https://en.wikipedia.org/wiki/RSA(cryptosystem)  

[output.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/crypto/rsa-output.txt) [chall.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/crypto/rsa-chall.py)  

---

We're given `chall.py` and `output.txt`. Here's `chall.py`:  

```py
from Crypto.Util.number import *

p = getPrime(1024)
q = getPrime(1024)

n = p*q
e = 123589168751396275896312856328164328381265978316578963271231567137825613822284638216416
m = bytes_to_long(b"nbctf{[REDACTED]}")

ct = (m^e) % n

print("n = ", n)
print("e = ", e)
print("ct = ", ct)
```

Seems like all that's different is that we're doing (m^e) % n. Except, in Python, ^ is the XOR function, which is a reversible function.  

Decryption follows easily as such:  

`ct = (m^e) % n`  

Since m^e < n because m is unpadded and thus both m and e are probably less than n, `ct = m^e  `  

`ct ^ e = (m ^ e) ^ e = m`  

Simple xor does the trick:  

```py
from Cryptodome.Util.number import long_to_bytes

n =  13431294979312769345517878088407659222785929563176888493659632690735510803353339825485161776891929296355466082338185199541755546384591261208929371208286410559187299345800125302598147388467283782373829399059130130575707550536466670447022349923395822077916588516101640779751198703879200863153859677174339078186779847910915309774616338231020176817201080756103027200290903849975398368943087868140010448011002364291104062990443568049879169811274854879262048473842331319786127894828031613201122015559660817797429013884663990368453887433480357502012963127000535358820517096295714967262963843868885674823702064175405493435873
e =  123589168751396275896312856328164328381265978316578963271231567137825613822284638216416
ct =  159269674251793083518243077048685663852794473778188330996147339166703385101217832722333

print(long_to_bytes(ct ^ e))
```

    nbctf{wh0_t0ld_m3_t0_u53_xors!?!?!?}