---
layout: writeup
category: BCA-CTF-2024
chall_description:
points: 100
solves: 134
tags: crypto chacha20
date: 2024-06-12
comments: false
---

I made this cool service that lets you protect your secrets with state-of-the-art encryption. It's so secure that we don't even tell you the key we used to encrypt your message!

`nc challs.bcactf.com 31594`

[server.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/chacha_server.py)  

---

Here's the Python source file:  

```py
from Crypto.Cipher import ChaCha20

from os import urandom

key = urandom(32)
nonce = urandom(12)

secret_msg = urandom(16).hex()

def encrypt_msg(plaintext):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(plaintext.encode()).hex()

print('Secret message:')
print(encrypt_msg(secret_msg))

print('\nEnter your message:')
user_msg = input()

if len(user_msg) > 256:
    print('\nToo long!')
    exit()

print('\nEncrypted:')
print(encrypt_msg(user_msg))

print('\nEnter decrypted secret message:')
decrypted_secret_msg = input()

if len(decrypted_secret_msg) == len(secret_msg):
    if decrypted_secret_msg == secret_msg:
        with open('../flag.txt') as file:
            print('\n' + file.read())
        exit()

print('\nIncorrect!')

```

Essentially, this is just an encryption oracle, in which we are allowed to encrypt a message once with standard ChaCha20 and then decrypt the server's previous encrypted message.  

Basically, the key idea is that ChaCha20 is a stream cipher. What that means is that it will generate a byte string and perform a XOR encryption with the provided ciphertext. The byte string is **deterministically** produced from the key and nonce.  

Notice how the key and nonce are the same for both the secret string encryption and the user's own encryption? Because of this, the byte string produced by ChaCha20 for both encryptions is the exact same! Therefore, we can simply send in several null bytes to be encrypted to get the byte string, and then XOR that with the server's encrypted secret message to get the plaintext!  

```py
from pwn import *
from binascii import *
from Crypto.Util.strxor import strxor

p = remote('34.23.70.45', 31100)

p.recvline()
ct = unhexlify(p.recvline().decode('ascii')[:-1])

p.recvrepeat(0.1)

p.sendline(b'\x00'*256)

p.recvuntil(b'Encrypted:\n')
ct1 = unhexlify(p.recvline().decode('ascii')[:-1])

p.recvrepeat(0.1)

pt = strxor(ct, ct1[:len(ct)])
p.sendline(pt)

p.interactive()
```

    bcactf{b3_C4rEFu1_wItH_crypT0Gr4phy_7d12be3b}