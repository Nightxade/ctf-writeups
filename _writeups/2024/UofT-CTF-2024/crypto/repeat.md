---
layout: writeup
category: UofT-CTF-2024
chall_description: N/A
points: 100
solves: 317
tags: crypto xor
date: 2024-1-15
comments: false
---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

I'm a known repeat offender when it comes to bad encryption habits. But the secrets module is secure, so you'll never be able to guess my key!  

Author: SteakEnthusiast  
[flag.enc](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2024/flag.enc)  
[gen.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2024/gen.py)  

---

We're given the ciphertext and a source file for the encryption. Here's `gen.py`:  
```py
import os
import secrets

flag = "REDACATED"
xor_key = secrets.token_bytes(8)

def xor(message, key):
    return bytes([message[i] ^ key[i % len(key)] for i in range(len(message))])

encrypted_flag = xor(flag.encode(), xor_key).hex()

with open("flag.enc", "w") as f:
    f.write("Flag: "+encrypted_flag)
```

Seems like a very standard XOR encryption.  

Conveniently, the key length is 8 bytes. This is crucial because we actually know the first 8 bytes of the flag, i.e. `uoftctf{`. Therefore, since XOR is a reversible function, we can relatively easily get the flag. See below:  

$$First\; 8\; bytes\; of\; ciphertext\; = ct[:8] = key \oplus \text{"uoftctf\{"}$$  
$$ct[:8] \oplus \text{"uoftctf\{"} = key \oplus \text{"uoftctf\{"} \oplus \text{"uoftctf\{"}$$  
$$ct[:8] \oplus \text{"uoftctf\{"} = key$$  

Therefore, we can easily get the key and decrypt the flag! Here's the short implementation:  

```py
from binascii import unhexlify
from Crypto.Util.strxor import strxor

ct = unhexlify("982a9290d6d4bf88957586bbdcda8681de33c796c691bb9fde1a83d582c886988375838aead0e8c7dc2bc3d7cd97a4")
key = strxor(ct[:8], b'uoftctf{')

def xor(message, key):
    return bytes([message[i] ^ key[i % len(key)] for i in range(len(message))])

flag = xor(ct, key)
print(flag)
```

Run the script to get the flag!  

    uoftctf{x0r_iz_r3v3rs1bl3_w17h_kn0wn_p141n73x7}