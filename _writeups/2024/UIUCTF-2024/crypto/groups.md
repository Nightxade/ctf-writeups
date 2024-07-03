---
layout: writeup
category: UIUCTF-2024
chall_description:
points: 431
solves: 105
tags: crypto carmichael dlp
date: 2024-07-02
comments: false
---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

My friend told me that cryptography is unbreakable if moduli are Carmichael numbers instead of primes. I decided to use this CTF to test out this theory.

`ncat --ssl groups.chal.uiuc.tf 1337`

[challenge.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/groups-challenge.py)  

---

Here's the Python source:  

```py
from random import randint
from math import gcd, log
import time
from Crypto.Util.number import *


def check(n, iterations=50):
    if isPrime(n):
        return False

    i = 0
    while i < iterations:
        a = randint(2, n - 1)
        if gcd(a, n) == 1:
            i += 1
            if pow(a, n - 1, n) != 1:
                return False
    return True


def generate_challenge(c):
    a = randint(2, c - 1)
    while gcd(a, c) != 1:
        a = randint(2, c - 1)
    k = randint(2, c - 1)
    return (a, pow(a, k, c))


def get_flag():
    with open('flag.txt', 'r') as f:
        return f.read()

if __name__ == '__main__':
    c = int(input('c = '))

    if log(c, 2) < 512:
        print(f'c must be least 512 bits large.')
    elif not check(c):
        print(f'No cheating!')
    else:
        a, b = generate_challenge(c)
        print(f'a = {a}')
        print(f'a^k = {b} (mod c)')
        
        k = int(input('k = '))

        if pow(a, k, c) == b:
            print(get_flag())
        else:
            print('Wrong k')
```

In short, this is simply solving the discrete log problem with the modulus is a Carmichael number. Essentially, Carmichael numbers are composite numbers that have the same property of the primes of Fermat's Little Theorem, which states that $$a^{p-1}=1\;(mod \;p)$$ for any prime `p`, such that `a` and `p` are coprime. Essentially, $$a^{n-1}=1\;(mod\;n)$$, such that `a` and `n` are coprime.  

Through a bit of research, I found out how to calculate large Carmichael numbers in [this post](https://math.stackexchange.com/questions/3029794/large-carmichael-number). Basically, you take an integer `k`, and check if $$6k+1$$, $$12k+1$$, and $$18k+1$$ are all prime. If they are, then $$(6k+1)(12k+1)(18k+1)$$ is a Carmichael number.  

With this, we can write a pretty quick generation script for a Carmichael number:  

```py
from Crypto.Util.number import isPrime
from tqdm import trange

for k in trange(2**171, 2**171 + 2**20):
    if isPrime(6*k+1) and isPrime(12*k+1) and isPrime(18*k+1):
        n = (6*k+1)*(12*k+1)*(18*k+1)
        print(n)
        break
```

Now, how do we solve the discrete log problem? Well, since our Carmichael number is actually the product of 3 primes that are each ~171 bits, this problem now becomes much easier to do, since our discrete log using a modulus of 512 bits now becomes equivalent to just doing 3 discrete logs using 3 different moduli of 171 bits. I actually kinda failed implementing it by hand, so I just [Alperton](https://www.alpertron.com.ar/DILOG.HTM) to just solve the discrete log problem. Plug it in to get `k`, then send it back to the server to get the flag!  

    uiuctf{c4rm1ch43l_7adb8e2f019bb4e0e8cd54e92bb6e3893}