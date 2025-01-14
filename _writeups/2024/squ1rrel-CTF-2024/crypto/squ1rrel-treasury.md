---
layout: writeup
category: squ1rrel-CTF-2024
chall_description:
points: 448
solves: 36
tags: squ1rrel-CTF-2024 crypto crypto/aes crypto/cbc
date: 2024-4-28
comments: false
---

We recently opened a new bank, our exchange rate is pretty poor though

`nc treasury.squ1rrel-ctf-codelab.kctf.cloud 1337`

[chall.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/squ1rrel-CTF-2024/chall.py)  

---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

Here's chall.py:  

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
import os
from secrets import KEY, FLAG
import random

ACCOUNT_NAME_CHARS = set([chr(i) for i in range(ord('a'), ord('z')+1)] + [chr(i) for i in range(ord('A'), ord('Z')+1)])
FLAG_COST = random.randint(10**13, 10**14-1)

def blockify(text: str, block_size: int):
    return [text[i:i+block_size] for i in range(0, len(text), block_size)]

def pad(blocks: list, pad_char: chr, size: int):
    padded = []
    for block in blocks:
        tmp = block
        if len(block) < size:
            tmp = tmp + pad_char*(size-len(tmp))
        elif len(block) > size:
            print("Inconsistent block size in pad")
            exit(1)
        padded.append(tmp)
    return padded

class Account:
    def __init__(self, iv: bytes, name: str, balance: int):
        self.__iv = iv
        self.__name = name
        self.__balance = balance

    def getIV(self):
        return self.__iv

    def getName(self):
        return self.__name

    def getBalance(self):
        return self.__balance

    def setBalance(self, new_balance):
        self.__balance = new_balance

    def getKey(self):
        save = f"{self.__name}:{self.__balance}".encode()
        blocks = blockify(save, AES.block_size)
        pblocks = pad(blocks, b'\x00', AES.block_size)
        cipher = AES.new(KEY, AES.MODE_ECB)
        ct = []
        for i, b in enumerate(pblocks):
            if i == 0:
                tmp = strxor(b, self.__iv)
                ct.append(cipher.encrypt(tmp))
            else:
                tmp = strxor(strxor(ct[i-1], pblocks[i-1]), b)
                ct.append(cipher.encrypt(tmp))
        ct_str = f"{self.__iv.hex()}:{(b''.join(ct)).hex()}"
        return ct_str

    def load(key: str):
        key_split = key.split(':')
        iv = bytes.fromhex(key_split[0])
        ct = bytes.fromhex(key_split[1])
        cipher = AES.new(KEY, AES.MODE_ECB)
        pt = blockify(cipher.decrypt(ct), AES.block_size)
        ct = blockify(ct, AES.block_size)
        for i, p in enumerate(pt):
            if i == 0:
                pt[i] = strxor(p, iv)
            else:
                pt[i] = strxor(strxor(ct[i-1], pt[i-1]), p)
        pt = b''.join(pt)
        pt_split = pt.split(b':')
        try:
            name = pt_split[0].decode()
        except Exception:
            name = "ERROR"
        balance = int(pt_split[1].strip(b'\x00').decode())
        return Account(iv, name, balance)

def accountLogin():
    print("\nPlease provide your account details.")
    account = input("> ").strip()
    account = Account.load(account)
    print(f"\nWelcome {account.getName()}!")
    while True:
        print("What would you like to do?")
        print("0 -> View balance")
        print(f"1 -> Buy flag ({FLAG_COST} acorns)")
        print("2 -> Save")
        opt = int(input("> ").strip())
        if opt == 0:
            print(f"Balance: {account.getBalance()} acorns\n")
        elif opt == 1:
            if account.getBalance() < FLAG_COST:
                print("Insufficient balance.\n")
            else:
                print(f"Flag: {FLAG}\n")
                account.setBalance(account.getBalance()-FLAG_COST)
        elif opt == 2:
            print(f"Save key: {account.getKey()}\n")
            break                


def accountNew():
    print("\nWhat would you like the account to be named?")
    account_name = input("> ").strip()
    dif = set(account_name).difference(ACCOUNT_NAME_CHARS)
    if len(dif) != 0:
        print(f"Invalid character(s) {dif} in name, only letters allowed!")
        print("Returning to main menu...\n")
        return
    account_iv = os.urandom(16)
    account = Account(account_iv, account_name, 0)
    print(f"Wecome to Squirrel Treasury {account.getName()}")
    print(f"Here is your account key: {account.getKey()}\n")

if __name__ == "__main__":
    while True:
        print(r"""
              ⠀⠀⠀⠀⠀⠀⠀ ⢀⣀⣤⣄⣀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢴⣶⠀⢶⣦⠀⢄⣀⠀⠠⢾⣿⠿⠿⠿⠿⢦⠀⠀ ___  __ _ _   _/ |_ __ _ __ ___| |           
⠀⠀⠀⠀⠀⠀⠀⠀⠺⠿⠇⢸⣿⣇⠘⣿⣆⠘⣿⡆⠠⣄⡀⠀⠀⠀⠀⠀⠀⠀/ __|/ _` | | | | | '__| '__/ _ \ |            
⠀⠀⠀⠀⠀⠀⢀⣴⣶⣶⣤⣄⡉⠛⠀⢹⣿⡄⢹⣿⡀⢻⣧⠀⡀⠀⠀⠀⠀⠀\__ \ (_| | |_| | | |  | | |  __/ |            
⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡈⠓⠀⣿⣧⠈⢿⡆⠸⡄⠀⠀⠀⠀|___/\__, |\__,_|_|_|  |_|  \___|_|            
⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣈⠙⢆⠘⣿⡀⢻⠀⠀⠀⠀        |_|                                    
⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠹⣧⠈⠀⠀⠀⠀ _____                                         
⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠈⠃⠀⠀⠀⠀/__   \_ __ ___  __ _ ___ _   _ _ __ ___ _   _ 
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀  / /\/ '__/ _ \/ _` / __| | | | '__/ _ \ | | |
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀ / /  | | |  __/ (_| \__ \ |_| | | |  __/ |_| |
⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀ \/   |_|  \___|\__,_|___/\__,_|_|  \___|\__, |
⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀                                         |___/ 
⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⣿⣿⠿⠿⠿⠿⠿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
              """)
        print("Welcome to squ1rrel Treasury! What would you like to do?")
        print("0 -> Login")
        print("1 -> Create new account")
        opt = int(input("> ").strip())
        if opt == 0:
            accountLogin()
        elif opt == 1:
            accountNew()

```

In short, this program emulates a login page with its own custom cipher for the account key. Notably, the account key controls the balance of acorns a user has. Our goal for this challenge is to modify the number of acorns in a user's balance.  

The custom cipher implemented is very similar to AES CBC mode, but with one key difference. Let's take a look at the load() function, i.e. the decryption function:  

```py
def load(key: str):
    key_split = key.split(':')
    iv = bytes.fromhex(key_split[0])
    ct = bytes.fromhex(key_split[1])
    cipher = AES.new(KEY, AES.MODE_ECB)
    pt = blockify(cipher.decrypt(ct), AES.block_size)
    ct = blockify(ct, AES.block_size)
    for i, p in enumerate(pt):
        if i == 0:
            pt[i] = strxor(p, iv)
        else:
            pt[i] = strxor(strxor(ct[i-1], pt[i-1]), p)
    pt = b''.join(pt)
    pt_split = pt.split(b':')
    try:
        name = pt_split[0].decode()
    except Exception:
        name = "ERROR"
    balance = int(pt_split[1].strip(b'\x00').decode())
    return Account(iv, name, balance)
```

If you take a look at this section:  

```py
if i == 0:
    pt[i] = strxor(p, iv)
else:
    pt[i] = strxor(strxor(ct[i-1], pt[i-1]), p)
```

You'll notice that the plaintext is decrypted by XORing the current plaintext block with the previous ciphertext block and the previous plaintext block. This is slightly different from AES CBC mode, in which the plaintext is decrypted by XORing the current plaintext block with the previous ciphertext block. See [this site](https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/) for a visual of how AES CBC decryption works.  

A common attack on AES CBC is to modify the IV in order to change the result of the first plaintext block. This is because we know that the IV will not be changed, unlike the rest of the blocks which are decrypted via AES ECB mode, and so we know exactly how it would affect the first plaintext block. For instance, consider the following modification to the IV and how it would affect the first plaintext block:  

$$pt_0 = AES.decrypt(ct) \oplus IV$$  
Where $$pt_0$$ is the original plaintext, ct is the ciphertext, and the IV is the initialization vector.  
Let's modify the IV:  
$$IV_{forged} = IV \oplus pt_0 \oplus b"injection string"$$  
$$pt_1 = AES.decrypt(ct) \oplus IV_{forged} = AES.decrypt(ct) \oplus IV \oplus pt_0 \oplus b"injection string"$$  
We can substitute in the first equation.  
$$pt_1 = pt_0 \oplus pt_0  \oplus b"injection string"$$  
$$pt_1 = b"injection string"$$  

Therefore, we have successfully modified the first plaintext block to become "injection string" instead of the original plaintext!  

That's how it would work for AES CBC, but what about this custom cipher...?  

Well, although this cipher is different, you might notice that the decryption of the very first block is the same as in AES CBC.  

```py
if i == 0:
    pt[i] = strxor(p, iv)
```

Thus, the exact same exploit should work.  

*Note that we can simply enter no name to get the balance to be entirely contained within the first plaintext block. Actually, the way I solved during the contest was to send 16 bytes for the name and get the balance entirely contained within the second plaintext block. It turns out the same exploit works for both methods, since the first plaintext block is XORed with the second plaintext block. I am guessing that the solution explained above is the unintended, and that my original solution of modifying the second plaintext block was the intended.  

Here's the solve script, which essentially overwrites the balance to be 99999999999999:  

```py
from pwn import *
from Crypto.Util.strxor import strxor
from binascii import *

p = remote('treasury.squ1rrel-ctf-codelab.kctf.cloud', 1337)

p.sendlineafter(b'\n> ', b'1')
# the below commented line does the same exploit but for modifying the second plaintext block
# p.sendlineafter(b'> ', b'a'*16)
p.sendlineafter(b'>', b'')
p.recvuntil(b': ')
key = p.recvline().decode('ascii')[:-1]
# key = input()

iv = unhexlify(key.split(':')[0])
iv = strxor(iv, b'\x00'*2 + b'9'*14)
key_mod = hexlify(iv) + b':' + key.split(':')[1].encode()
# print(key_mod)

p.sendlineafter(b'\n> ', b'0')
p.sendlineafter(b'> ', key_mod)
p.sendlineafter(b'\n> ', b'1')

p.interactive()
```

    squ1rrel{7H3_4C0rN_3NCrYP710N_5CH3M3_15_14CK1N6}