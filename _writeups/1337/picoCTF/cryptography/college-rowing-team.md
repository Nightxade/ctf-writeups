---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/a2Nwy5e.png
points: 250
solves: 964
tags: picoCTF crypto crypto/rsa crypto/unpadded
date: 1337-01-01
comments: false
---

I just joined my college's rowing team! To make a good first impression, I started sending my teammates positive automated messages every day. I even send them flags from time to time!  

|Download encrypted-messages.txt|[encrypted-messages.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/college-rowing-encrypted-messages.txt)|
|Download encrypt.py|[encrypt.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/college-rowing-encrypt.py)|

---

We’re given two files, `encrypt.py` and `encrypted-messages.txt`.  

Let’s take a look at encrypt.py:  

```py
#!/usr/bin/env python3

import random
from Crypto.Util.number import getPrime, bytes_to_long

with open('flag.txt', 'rb') as f:
    flag = f.read()

msgs = [
    b'I just cannot wait for rowing practice today!',
    b'I hope we win that big rowing match next week!',
    b'Rowing is such a fun sport!'
        ]

msgs.append(flag)
msgs *= 3
random.shuffle(msgs)

for msg in msgs:
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 3
    m = bytes_to_long(msg)
    c = pow(m, e, n)
    with open('encrypted-messages.txt', 'a') as f:
        f.write(f'n: {n}\n')
        f.write(f'e: {e}\n')
        f.write(f'c: {c}\n\n')
```

It seems like three messages + the flag are each encrypted 3 times with RSA, in a random order. Additionally, the public exponent e is always 3, which perhaps implies that we can use Hastad’s broadcast attack.  

Let’s check out the encrypted-messages.txt file now. There’s something weird with the file... notice it?  

The key observation to make here is that some of the ciphertexts are the **same**. Presumably, these identical ciphertexts originate from the same message, but why would they be identical?  

We know that $$m\equiv e^{c}\;(mod\;n)$$, and none of the n’s are identical. If we have different `n`’s, and $$m^{e}\ge n$$, we should get a different ciphertext `c` each time.  

Wait… so maybe that means $$m^{e}<n$$. So this is likely unpadded RSA, meaning the messages were not padded with extra characters and the modulus n was never really used in the encryption process. The low public exponent also supports this, as, when `e` is as low as 3, it is not uncommon for $$m^{e}<n$$.  

That means $$m^{e}=c$$, so we can simply take the *cube root* of each ciphertext to find the original messages.  

We can write a short python script for this and test all possible ciphertexts:  
```py
from gmpy2 import iroot

c = 868938910067249952838548130143908771727351638690361694965654617377419268292732524264841389055007122795668815782628236966204158649165906515577110359828106902273777>

r = iroot(c, 3)
r = format(r[0], 'x')
r = bytearray.fromhex(r).decode('ASCII')
print(r)

```
Eventually, using the above ciphertext value will return the flag:

    picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}
