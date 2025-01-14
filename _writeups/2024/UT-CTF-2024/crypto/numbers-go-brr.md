---
layout: writeup
category: UT-CTF-2024
chall_description:
points: 481
solves: 228
tags: UT-CTF-2024 crypto crypto/random crypto/aes crypto/oracle
date: 2024-4-1
comments: false
---

I wrote an amazing encryption service. It is definitely flawless, so I'll encrypt the flag and give it to you.

By jocelyn (@jocelyn3270 on discord)

`nc betta.utctf.live 7356`  

[main-brr.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UT-CTF-2024/main-brr.py)  

---

We're provided a Python source file:  

```py
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time

seed = int(time.time() * 1000) % (10 ** 6)
def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def encrypt(message):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext.hex()

print("Thanks for using our encryption service! To get the encrypted flag, type 1. To encrypt a message, type 2.")
while True:
    print("What would you like to do (1 - get encrypted flag, 2 - encrypt a message)?")
    user_input = int(input())
    if(user_input == 1):
        break

    print("What is your message?")
    message = input()
    print("Here is your encrypted message:", encrypt(message.encode()))


flag = open('./src/flag.txt', 'r').read()
print("Here is the encrypted flag:", encrypt(flag.encode()))
```

So, basically, we're provided an AES oracle. It is seeded with a random number in the range [0, 10**6), which is used to calculate the keys for all encryptions.  

10**6 is a small seed space. Therefore, this challenge is as simple as brute-forcing the seed. We can simply ask for the encrypted flag, and try all possible seeds (and each resulting key for the first encryption) and try to decrypt to get the flag! See the following implementation:  

```py
from pwn import *
from Crypto.Cipher import AES
from binascii import *
from tqdm import trange

p = remote('betta.utctf.live', 7356)
# seed = int(time.time() * 1000) % (10 ** 6)
def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

p.recvuntil(b'?\n')
p.sendline(b'1')
ct = p.recvline().decode('ascii')[:-1].split(' ')[-1]

def decrypt(ct):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    return pt

for seed in trange(10**6):
    pt = decrypt(unhexlify(ct))
    if b'flag' in pt:
        print(pt)
        break
```

Run the script to get the flag!  

    utflag{deep_seated_and_recurring_self-doubts}