---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 285
solves: 56
tags: Wolv-CTF-2024 crypto crypto/aes crypto/oracle crypto/roll-your-own
date: 2024-3-19
comments: false
---

We managed to log into doubledelete's email server. Hopefully this should give us some leads...  

`nc blocked2.wolvctf.io 1337`  

[server.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/crypto/blocked-2/server.py) 

---

We're given a Python source:  

```py

import random
import secrets
import sys
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor


MASTER_KEY = secrets.token_bytes(16)


def encrypt(message):
    if len(message) % 16 != 0:
        print("message must be a multiple of 16 bytes long! don't forget to use the WOLPHV propietary padding scheme")
        return None

    iv = secrets.token_bytes(16)
    cipher = AES.new(MASTER_KEY, AES.MODE_ECB)
    blocks = [message[i:i+16] for i in range(0, len(message), 16)]

    # encrypt all the blocks
    encrypted = [cipher.encrypt(b) for b in [iv, *blocks]]

    # xor with the next block of plaintext
    for i in range(len(encrypted) - 1):
        encrypted[i] = strxor(encrypted[i], blocks[i])

    return iv + b''.join(encrypted)


def main():
    message = open('message.txt', 'rb').read()

    print("""                 __      __
 _      ______  / /___  / /_ _   __
| | /| / / __ \\/ / __ \\/ __ \\ | / /
| |/ |/ / /_/ / / /_/ / / / / |/ /
|__/|__/\\____/_/ .___/_/ /_/|___/
              /_/""")
    print("[          email portal          ]")
    print("you are logged in as doubledelete@wolp.hv")
    print("")
    print("you have one new encrypted message:")
    print(encrypt(message).hex())

    while True:
        print(" enter a message to send to dree@wolp.hv, in hex")
        s = input(" > ")
        message = bytes.fromhex(s)
        print(encrypt(message).hex())


main()

```

Basically, the encryption process is as follows:  

1. A secret MASTER_KEY is generated for all encryptions in a single session  
2. The message is processed, and is ensured to be a multiple of 16  
3. A random IV is generated for each encryption  
4. An AES cipher in ECB mode is created with the session's MASTER_KEY  
5. The message is split into blocks of 16  
6. The IV and blocks are all encrypted via the AES ECB to form the encrypted array  
7. Each element of the encrypted array is XORed with the next block of plaintext. Essentially, the IV is XORed with the first block of plaintext, the first block of plaintext is XORed with the second block, etc. et.  
8. The IV + the elements of encrypted are returned  

There are a couple key things to note here. First, we are provided the original IV. Second, the last encrypted block is **not** XORed with anything, so it is just the AES ECB encryption of the last block of plaintext.  

After a long time of thinking (45-60 minutes), I finally managed to figure it out. It all lies in the second realization, that the last encrypted block is not XORed with anything.  

We are provided an encryption oracle, so we can encrypt anything we want. Well, what if we sent in just the IV of the ciphertext of the original email we need to decrypt? Well, the very last 16 bytes of the returned ciphertext would be only the AES ECB encryption of the IV.  

Well, the first block of the encrypted array is equivalent to xor(AES ECB encryption of the IV, first block of plaintext). Well, we can just XOR this first block of the encrypted array with the value we have found for the AES ECB encryption of the IV to receive the first block of plaintext!  

Once we do that, we can simply continue this down the blocks, with the first block of plaintext now replacing the IV. We'll send in the first block of plaintext to be encrypted, take the last 16 bytes of the result and XOR it with the second block of the encrypted array of the original ciphertext to get the second plaintext.  

Here's the implementation:  

```py
from pwn import *
from Crypto.Util.strxor import strxor
import binascii

p = remote('blocked2.wolvctf.io', 1337)

p.recvuntil(b'message:\n')
ct = p.recvline().decode('ascii')[:-1]
# print(ct)

current_plain = ct[:32]
for i in range(len(ct)//32 - 1):
    p.sendlineafter(b'> ', current_plain)
    ct1 = p.recvline().decode('ascii')[:-1]
    current_plain = strxor(binascii.unhexlify(ct[32*(i+1):32*(i+2)]), binascii.unhexlify(ct1[-32:]))
    print(current_plain.decode('ascii'), end='')
    current_plain = binascii.hexlify(current_plain)
```

This decrypts the following message:  

```
those wolvsec nerds really think they're "good at security" huh... running the ransomware was way too easy. i've uploaded their files to our secure storage, let me know when you have them
-doubledelete@wolp.hv
wctf{s0m3_g00d_s3cur1ty_y0u_h4v3_r0lling_y0ur_0wn_crypt0_huh}
```

There's the flag!  

    wctf{s0m3_g00d_s3cur1ty_y0u_h4v3_r0lling_y0ur_0wn_crypt0_huh}