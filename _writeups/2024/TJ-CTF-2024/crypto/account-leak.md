---
layout: writeup
category: TJ-CTF-2024
chall_description:
points: 134
solves: 86
tags: TJ-CTF-2024 crypto crypto/rsa
date: 2024-5-19
comments: false
---

Uncrackable password? I thought this was a CTF; get me my friends minecraft password pls <3

`nc tjc.tf 31601`

[server.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/account-leak/server.py)  

---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

Here's the Python source:  

```py
#!/usr/local/bin/python3.10 -u

import time
from Crypto.Util.number import getPrime, getRandomInteger, getRandomNBitInteger

flag = open("flag.txt").read().strip()
p = getPrime(512)
q = getPrime(512)

sub = getRandomInteger(20)

# hehe u cant guess it since its random :P
my_password = getRandomNBitInteger(256)

n = p*q
c = pow(my_password, 65537, n)
dont_leak_this = (p-sub)*(q-sub)


def gamechat():
    print("<Bobby> i have an uncrackable password maybe")
    print(f"<Bobby> i'll give you the powerful numbers, {c} and {n}")
    print("<Bobby> gl hacking into my account")
    print("<Bobby> btw do you want to get my diamond stash")
    resp = input("<You> ")
    if (resp.strip() == "yea"):
        print("<Bobby> i'll send coords")
        print(f"<Bobby> {dont_leak_this}")
        print("<Bobby> oop wasnt supposed to copypaste that")
        print("<Bobby> you cant crack my account tho >:)")
        tic = time.time()
        resp = input("<You> ")
        toc = time.time()
        if (toc-tic >= 2.5):
            print("<Bobby> you know I can reset my password faster than that lol")
        elif (resp.strip() != str(my_password)):
            print("<Bobby> lol nice try won't give password that easily")
        else:
            print("<Bobby> NANI?? Impossible?!?")
            print("<Bobby> I might as wel give you the flag")
            print(f"<Bobby> {flag}")
    else:
        print("<Bobby> bro what, who denies free diamonds?")
    print("Bobby has left the game")


gamechat()

```

Seems like another RSA challenge. We're provided a leak equivalent to `(p-sub)(q-sub)`, where `sub` is a random 20-bit integer. Well, we can actually do a bit of math to turn this leak into knowledge of phi(n), i.e. Euler's totient, which will allow us to decrypt the password ciphertext and get the flag:  

$$leak = n - sub*(p + q - sub)$$

$$n - leak = sub*(p + q - sub)$$

$$(n - leak)//sub = p + q - sub$$

$$p + q = (n - leak)//sub + sub$$

$$phi = (p-1)(q-1) = pq - (p + q) + 1 = n - (p + q) + 1$$

Now, in order to get `sub`, we can just brute-force it, knowing that it is a factor of $$n - leak$$  

```py
from pwn import *
from sympy.ntheory import factorint
from Crypto.Util.number import *

r = remote('tjc.tf', 31601)
r.recvuntil(b', ')
res = r.recvline().decode("ascii").split(' ')
c = int(res[0])
n = int(res[-1])
r.sendlineafter(b'<You> ', b'yea')
r.recvline()
leak = int(r.recvline().decode('ascii')[:-1].split()[-1])

sub = -1
for i in range(1<<19, 1<<20): # 50% chance for it to be 20 bits long
    if (n - leak) % i == 0:
        print(i)
        sub = i
        break

assert sub.bit_length() == 20

p_plus_q = (n - leak)//sub + sub
phi = n - p_plus_q + 1
d = inverse(65537, phi)
pt = pow(c, d, n)
r.sendlineafter(b'<You> ', str(pt).encode())
r.interactive()
```

    tjctf{h3y_wh3r3_d1d_my_d1am0nds_g0_th3y_w3r3_ju5t_h3r3}