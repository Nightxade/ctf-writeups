---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 50
solves: 188
tags: crypto crypto/otp
date: 2024-3-19
comments: false
---

One-time pads are perfectly information-theoretically secure, so I should be safe, right?  

[chall.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/chall.py)  
[eFlag.bmp](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/eFlag.bmp)  
[eWolverine.bmp](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/eWolverine.bmp)  

---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

We're provided a Python source file, and two images. Here's the source file:  

```py
from Crypto.Random import random, get_random_bytes

BLOCK_SIZE = 16

with(open('./genFiles/wolverine.bmp', 'rb')) as f:
    wolverine = f.read()
with(open('./genFiles/flag.bmp', 'rb')) as f:
    flag = f.read()

w = open('eWolverine.bmp', 'wb')
f = open('eFlag.bmp', 'wb')

f.write(flag[:55])
w.write(wolverine[:55])

for i in range(55, len(wolverine), BLOCK_SIZE):
    KEY = get_random_bytes(BLOCK_SIZE)
    w.write(bytes(a^b for a, b in zip(wolverine[i:i+BLOCK_SIZE], KEY)))
    f.write(bytes(a^b for a, b in zip(flag[i:i+BLOCK_SIZE], KEY)))
```

Seems like we're just doing a one-time pad on two files with the same key. This is a standard vulnerability in OTP, which is implied in the name. All OTP keys should be used only **once**. To expose this vulnerability, we can XOR the two images, because it will reveal information about the images. See below:  

$$ct1 = pt1 \oplus key$$  
$$ct2 = pt2 \oplus key$$  
$$ct1 \oplus ct2 = pt1 \oplus pt2 \oplus key \oplus key = pt1 \oplus pt2$$  

For images, this may result in some information being revealed in the image result of the XOR. Using stegsolve, we can use the Image Combiner --> XOR mode to XOR the two images and reveal this information!  

<img src="https://imgur.com/a1hnRyo" alt="[description]" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

    wctf{D0NT_R3CYCLE_K3Y5}