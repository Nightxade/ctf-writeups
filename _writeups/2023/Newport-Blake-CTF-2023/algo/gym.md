---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/XcntmTZ.png
points: 438
solves: 50
tags: algo greedy
date: 12-4-2023
comments: false
---

Bro kroot.  

Ignore the time/memory/input/output section of the pdf.  

`nc chal.nbctf.com 30270`  

[gym.pdf](https://github.com/Nightxade/ctf-writeups/assets/CTFs/Newport-Blake-CTF-2023/algo/gym.pdf)  

---

Okay, so we're given a sequence of good and bad steps, and given that we can step with maximum length k, we must try to make it to the top step by stepping on only bad steps. The path we take must include the minimum number of steps, which we will send to the service. If it is impossible, send -1.  

The solution to this is a very simple greedy algorithm. It is evidently optimal to step as far as you can at each step. Therefore, it is suitable to, at each step, try and step k length, and subsequently decrease the step length until a good step is found. If no good step is found at any point in the loop, the test case is impossible.  

Here is my implementation of the solution:  

```py
from pwn import *

conn = remote('chal.nbctf.com', 30270)

t = int(conn.recvline().decode('ascii')[:-1])

for z in range(t):
    n,k = conn.recvline().decode('ascii')[:-1].split(' ')
    n = int(n)
    k = int(k)

    stairs = conn.recvline().decode('ascii')[:-1]

    print(n,k)
    print(stairs)

    index = 0
    steps = 0
    impossible = False
    while not impossible and index != n - 1:
        validstep = False
        for i in range(min(index + k, n - 1), index, -1):
            if stairs[i] == "0":
                index = i
                validstep = True
                steps += 1
                break
        
        if not validstep:
            impossible = True
            
    if impossible: conn.sendline(b"-1")
    else: conn.sendline(str(steps).encode())

print(conn.recv().decode('ascii'))
```

    nbctf{Why_4r3_y0u_S0_gr33DY}