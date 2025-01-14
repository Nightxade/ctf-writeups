---
layout: writeup
category: Cyber-Cooperative-CTF-2023
chall_description:
points: 100
solves: 235
tags: forensics forensics/binwalk
date: 2023-12-19
comments: false
---

This little baby is figuring out how to computer! It looks like the baby hid some of my files though. I have no idea what to do, can you get my files back?

[babyhide.jpg](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Cyber-Cooperative-CTF-2023/forensics/babyhide.jpeg)  

---

Running `binwalk` on the file tells us there is a PDF file located at offset 0x1CAB6. We can write a Python program to extract it:  

```py
r = open('babyhide.jpeg', 'rb').read()
w = open('babyhide.pdf', 'wb')

w.write(r[0x1CAB6:])
w.close()
```

Opening up the pdf gets us the flag!  

    flag{baby_come_back}