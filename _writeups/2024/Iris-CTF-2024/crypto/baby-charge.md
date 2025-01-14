---
layout: writeup
category: Iris-CTF-2024
chall_description: 
points: 50
solves: 151
tags: crypto crypto/chacha20 crypto/oracle
date: 2024-1-7
comments: false
---

For your first assignment, break ChaCha20!  
`nc babycha.chal.irisc.tf 10100`  
[babycha.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/babycha.tar.gz)  

---

We're given an encryption oracle with two options -- 1. encrypt any plaintext we want and 2. encrypt the flag.  

We are also given the source code for the service. Here it is:  

```py
# https://en.wikipedia.org/wiki/Salsa20#ChaCha20_adoption

from Crypto.Util.number import long_to_bytes, bytes_to_long
import secrets

def ROTL(a, b):
    return (((a) << (b)) | ((a % 2**32) >> (32 - (b)))) % 2**32

def qr(x, a, b, c, d):
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d],16)
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b],12)
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d], 8)
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b], 7)

ROUNDS = 20

def chacha_block(inp):
    x = list(inp)
    for i in range(0, ROUNDS, 2):
        qr(x, 0, 4, 8, 12)
        qr(x, 1, 5, 9, 13)
        qr(x, 2, 6, 10, 14)
        qr(x, 3, 7, 11, 15)

        qr(x, 0, 5, 10, 15)
        qr(x, 1, 6, 11, 12)
        qr(x, 2, 7, 8, 13)
        qr(x, 3, 4, 9, 14)

    return [(a+b) % 2**32 for a, b in zip(x, inp)]

def chacha_init(key, nonce, counter):
    assert len(key) == 32
    assert len(nonce) == 8

    state = [0 for _ in range(16)]
    state[0] = bytes_to_long(b"expa"[::-1])
    state[1] = bytes_to_long(b"nd 3"[::-1])
    state[2] = bytes_to_long(b"2-by"[::-1])
    state[3] = bytes_to_long(b"te k"[::-1])

    key = bytes_to_long(key)
    nonce = bytes_to_long(nonce)

    for i in range(8):
        state[i+4] = key & 0xffffffff
        key >>= 32

    state[12] = (counter >> 32) & 0xffffffff
    state[13] = counter & 0xffffffff
    state[14] = (nonce >> 32) & 0xffffffff
    state[15] = nonce & 0xffffffff

    return state

state = chacha_init(secrets.token_bytes(32), secrets.token_bytes(8), 0)
buffer = b""
def encrypt(data):
    global state, buffer

    output = []
    for b in data:
        if len(buffer) == 0:
            buffer = b"".join(long_to_bytes(x).rjust(4, b"\x00") for x in state)
            state = chacha_block(state)
        output.append(b ^ buffer[0])
        buffer = buffer[1:]
    return bytes(output)

flag = b"fake_flag{FAKE_FLAG}"

if __name__ == "__main__":
    print("""This cipher is approved by Disk Jockey B.

1. Encrypt input
2. Encrypt flag
""")

    while True:
        inp = input("> ")

        match inp:
            case '1':
                print(encrypt(input("? ").encode()).hex())
            case '2':
                print(encrypt(flag).hex())
            case _:
                print("Bye!")
                exit()
```

Most of the program involves carrying out the actual encryption.  

After researching ChaCha20 and testing some of the program's functions in my own local file, I realized a few key things.

1. Similar to AES, ChaCha20 shuffles the bytes to make it practically impossible to determine the `state`
2. ChaCha20 is a stream cipher, so if we can find the `state`, we can decrypt easily
3. The initialization of ChaCha20 in this program is not random in certain parts
4. ChaCha20's `state` changes in blocks of 64 bytes
5. ChaCha20's next `state` is determined solely by the previous `state`.

After a while of trying to figure out how to exploit 3, I realized it was somewhat of a red herring. In fact, this problem is trivial if you focus on the other aspects of this program.  

Essentially, since we are provided an encryption oracle, if we send in 64 null bytes to be encrypted, the oracle will return the current `state`. Knowing the current `state`, it is easy to find the next state by copying the provided code, and thus we can easily XOR it with the ciphertext of the flag and get the flag!  

Here is the implementation:  

```py
from pwn import *
from Crypto.Util.number import long_to_bytes
import binascii

def ROTL(a, b):
    return (((a) << (b)) | ((a % 2**32) >> (32 - (b)))) % 2**32

def qr(x, a, b, c, d):
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d],16)
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b],12)
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d], 8)
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b], 7)

ROUNDS = 20

def chacha_block(inp):
    x = list(inp)
    for i in range(0, ROUNDS, 2):
        qr(x, 0, 4, 8, 12)
        qr(x, 1, 5, 9, 13)
        qr(x, 2, 6, 10, 14)
        qr(x, 3, 7, 11, 15)

        qr(x, 0, 5, 10, 15)
        qr(x, 1, 6, 11, 12)
        qr(x, 2, 7, 8, 13)
        qr(x, 3, 4, 9, 14)

    return [(a+b) % 2**32 for a, b in zip(x, inp)]

p = remote('babycha.chal.irisc.tf', 10100)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'? ', b'\x00'*64)
state_hex = p.recvuntil(b'\n')[:-1]
# print(state_hex)
state = []
for i in range(0, len(state_hex), 8):
    state.append(int(state_hex[i:i+8], 16))

state = chacha_block(state)
# print(state)
buffer = b"".join(long_to_bytes(x).rjust(4, b"\x00") for x in state)

p.sendlineafter(b'> ', b'2')
ct = p.recvuntil(b'\n')[:-1]
# print(ct)
ct = binascii.unhexlify(ct)

flag = ''
for i in range(len(ct)):
    flag += chr(ct[i] ^ buffer[i])

print(flag)
```

Running the script gets the flag!  

    irisctf{initialization_is_no_problem}