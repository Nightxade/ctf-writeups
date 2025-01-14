---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 100
solves: 207
tags: crypto crypto/random
date: 2024-3-19
comments: false
---

It's pretty easy to find random integers if you know the seed, but what if every second has a different seed?  

[chal_time.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/crypto/limited-1/chal_time.py) 

---

We're provided a Python source:  

```py
import time
import random
import sys

if __name__ == '__main__':
    flag = input("Flag? > ").encode('utf-8')
    correct = [189, 24, 103, 164, 36, 233, 227, 172, 244, 213, 61, 62, 84, 124, 242, 100, 22, 94, 108, 230, 24, 190, 23, 228, 24]
    time_cycle = int(time.time()) % 256
    if len(flag) != len(correct):
        print('Nope :(')
        sys.exit(1)
    for i in range(len(flag)):
        random.seed(i+time_cycle)
        if correct[i] != flag[i] ^ random.getrandbits(8):
            print('Nope :(')
            sys.exit(1)
    print(flag)

```

So, basically, the seed for the `random.getrandbits(8)` call is changing for each byte. This is very easily brute-forceable, by simply looping over all possible initial seeds (only 256 possible values), decrypting, and then checking is the result is all ASCII to limit the results that need to be manually checked.  

```py
import random

correct = [189, 24, 103, 164, 36, 233, 227, 172, 244, 213, 61, 62, 84, 124, 242, 100, 22, 94, 108, 230, 24, 190, 23, 228, 24]
randvals = []

for i in range(256 + len(correct)):
    random.seed(i)
    randvals.append(random.getrandbits(8))

for i in range(256):
    curr = b''
    isascii = True
    for j in range(len(correct)):
        x = correct[j] ^ randvals[i + j]
        if x >= 128:
            isascii = False
            break
        curr += chr(x).encode()
    if not isascii: continue
    print(curr)
```

Alternatively, since we know the prefix of the flag is `wctf`, we can check which initial seed values result in this prefix, and then easily decrypt from there.  

```py
import random

correct = [189, 24, 103, 164, 36, 233, 227, 172, 244, 213, 61, 62, 84, 124, 242, 100, 22, 94, 108, 230, 24, 190, 23, 228, 24]

seed = -1
for i in range(256):
    random.seed(i)
    f1 = correct[0] ^ random.getrandbits(8)
    random.seed(i + 1)
    f2 = correct[1] ^ random.getrandbits(8)
    if f1 == ord('w') and f2 == ord('c'):
        seed = i
        break

for j in range(len(correct)):
    random.seed(seed + j)
    print(chr(correct[j] ^ random.getrandbits(8)), end='')
```

Both scripts result in the flag!  

    wctf{f34R_0f_m1ss1ng_0ut}