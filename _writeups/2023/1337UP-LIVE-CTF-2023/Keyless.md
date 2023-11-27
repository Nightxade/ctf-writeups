---
layout: writeup
category: 1337UP-LIVE-CTF-2023
chall_description: https://i.imgur.com/R0cMpLi.png
points: 100
solves: 282
tags: crypto rev
date: 2023-11-26
comments: false
---

My friend made a new encryption algorithm. Apparently it's so advanced, you don't even need a key!  
[flag.txt.enc](https://github.com/Nightxade/ctf-writeups/assets/CTFs/1337-UP-LIVE-CTF-2023/flag.txt.enc)
[encrypt.py](https://github.com/Nightxade/ctf-writeups/assets/CTFs/1337-UP-LIVE-CTF-2023/encrypt.py)

---

We're given the following encrypt.py:
```py
def encrypt(message):
    encrypted_message = ""
    for char in message:
        a = (ord(char) * 2) + 10
        b = (a ^ 42) + 5
        c = (b * 3) - 7
        encrypted_char = c ^ 23
        encrypted_message += chr(encrypted_char)
    return encrypted_message

flag = "INTIGRITI{REDACTED}"
encrypted_flag = encrypt(flag)

with open("flag.txt.enc", "w") as file:
    file.write(encrypted_flag)
```
and a flag.txt.enc file.  

Seems pretty simple... right? And you'd be correct for the most part. Seemingly all you have to do is reverse the encryption, which is fairly simple.  
However, there's a small issue that messes up this decryption if you just let Python convert from int to bytes! It doesn't convert properly for characters with larger UTF codes. Instead, we can use an online tool to convert the ciphertext to its UTF-32 codes! Once we get that, it's simple to write a short script to decrypt and get the flag!  

    INTIGRITI{m4yb3_4_k3y_w0uld_b3_b3773r_4f73r_4ll}

The implementation follows as such:
```py
arr = [0x23d, 0x1bb, 0x1c7, 0x23d, 0x209, 0x183, 0x23d, 0x1c7, 0x23d, 0x391, 0x265, 0x107, 0x29d, 0x2a3, 0x101, 0x2b9, 0x107, 0x2b9, 0x271, 0x101, 0x29d, 0x2b9, 0x269, 0x0df, 0x2b5, 0x277, 0x2e7, 0x2b9, 0x2a3, 0x101, 0x2b9, 0x2a3, 0x101, 0x0e9, 0x0e9, 0x101, 0x243, 0x2b9, 0x107, 0x2eb, 0x0e9, 0x101, 0x243, 0x2b9, 0x107, 0x277, 0x277, 0x385]

m = 'INTIGRITI{'
for i in range(len(m), len(arr)):
    c = arr[i]
    c ^= 23
    c = (c + 7)//3
    c = (c - 5) ^ 42
    c = (c - 10)//2
    m += chr(c)
print(m)
```