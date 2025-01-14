---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 253
solves: 60
tags: crypto crypto/aes crypto/aes-ecb crypto/oracle
date: 2024-3-19
comments: false
---

Don't worry, the interns wrote this one.  

`nc tagseries1.wolvctf.io 1337`  

[chal.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/crypto/tag-series-1/chal.py) 

---

We're provided a Python source:  

```py
import sys
import os
from Crypto.Cipher import AES

MESSAGE = b"GET FILE: flag.txt"
QUERIES = []
BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)


def oracle(message: bytes) -> bytes:
    aes_ecb = AES.new(KEY, AES.MODE_ECB)
    return aes_ecb.encrypt(message)[-BLOCK_SIZE:]


def main():
    for _ in range(3):
        command = sys.stdin.buffer.readline().strip()
        tag = sys.stdin.buffer.readline().strip()
        if command in QUERIES:
            print(b"Already queried")
            continue

        if len(command) % BLOCK_SIZE != 0:
            print(b"Invalid length")
            continue

        result = oracle(command)
        if command.startswith(MESSAGE) and result == tag and command not in QUERIES:
            with open("flag.txt", "rb") as f:
                sys.stdout.buffer.write(f.read())
                sys.stdout.flush()
        else:
            QUERIES.append(command)
            assert len(result) == BLOCK_SIZE
            sys.stdout.buffer.write(result + b"\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

```

This is a basic AES ECB encryption oracle. We are allowed to encrypt 3 times, and we are not allowed to encrypt the same thing more than once. We have to pass a plaintext and the corresponding encryption of it to get the flag. This plaintext must also begin with a specified prefix.  

However, notably the encryption function only returns the last 16 bytes of the AES ECB encryption. This is equivalent to the last block, and will remain the same if the last 16 bytes of two plaintexts are the same.  

Therefore, this challenge is as simple as sending two different plaintexts. The second must include the prefix, and the last 16 bytes must be the same as the last 16 bytes of the first, so that the result of the encryption function is the same for both inputs. Here's the implementaion:  

```py
from pwn import *

p = remote('tagseries1.wolvctf.io', 1337)
prefix = 'GET FILE: flag.txt'

p.recvline()
p.sendline(b'a'*16)
p.sendline(b'a')
tag = p.recvline()[:-1]
print(tag)

payload = prefix.encode() + b'a'*(16 - (len(prefix) % 16)) + b'a'*16
assert len(payload) % 16 == 0

p.sendline(payload)
p.sendline(tag)
print(p.recvrepeat(1))
```

Run the script to get the flag!  

    wctf{C0nGr4ts_0n_g3tt1ng_p4st_A3S}