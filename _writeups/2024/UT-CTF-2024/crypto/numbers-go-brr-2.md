---
layout: writeup
category: UT-CTF-2024
chall_description:
points: 831
solves: 126
tags: crypto crypto/random crypto/aes crypto/oracle
date: 2024-4-1
comments: false
---

A spiritual successor the first.

By jocelyn (@jocelyn3270 on discord)

`nc betta.utctf.live 2435`

[main-brr2.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UT-CTF-2024/main-brr2.py)  

---

We're provided a Python source file:  

```py
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import random

seed = random.randint(0, 10 ** 6)
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
    return key.hex(), ciphertext.hex()


print("Thanks for using our encryption service! To get the start guessing, type 1. To encrypt a message, type 2.")
print("You will need to guess the key (you get 250 guesses for one key). You will do this 3 times!")

for i in range(3):
    seed = random.randint(0, 10 ** 6)
    print("Find the key " + str(i + 1) + " of 3!")
    key = encrypt(b"random text to initalize key")[0]
    while True:
        print("What would you like to do (1 - guess the key, 2 - encrypt a message)?")
        user_input = int(input())
        if(user_input == 1):
            break

        print("What is your message?")
        message = input()
        key, ciphertext = encrypt(message.encode())
        print("Here is your encrypted message:", ciphertext)
    print("You have 250 guesses to find the key!")
    
    found = False
    for j in range(250):
        print("What is your guess (in hex)?")
        guess = str(input()).lower()
        if guess == key:
            print("You found the key!")
            found = True
            break
        else:
            print("That is not the key!")

    if not found:
        print("You did not find the key!")
        exit(0)


flag = open('/src/flag.txt', 'r').read();
print("Here is the flag:", flag)
```

Seems similar to the first Numbers go brr challenge. However, in this one, we are not decrypting a flag, but instead finding a key 3 times in a row.  

However, we can exploit the same nature of the encryption scheme in both challenges, i.e. the seed space is of size 10**6, which is small enough to brute force.  

Essentially, for each seed we're testing, we can first initialize the state of the key, given that one encryption is done immediately before we are allowed to do anything (for each iteration of the program's for loop). Then, we can ask for an encryption of any plaintext. We can then use the same exact encrypt() function on our local machine to test if the ciphertext returned by the program matches up with our locally produced ciphertext. If it does, that means we have the right seed. At this point, after calling the encrypt() function on our local machine, it should have already updated the key to the right value, so all we need to do is submit that to get the flag!  

Here's the full implementation:  

```py
from pwn import *
from Crypto.Cipher import AES
from binascii import *
from tqdm import trange
from Crypto.Util.Padding import pad

p = remote('betta.utctf.live', 2435)
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
    return key.hex(), ciphertext.hex()

p.recvline()
p.recvline()
p.recvline()
p.recvline()
# p.sendline(b'2')
# p.recvline()
# m = b'a'
# p.sendline(m)
# ct = p.recvline().decode('ascii')[:-1].split(' ')[-1]
# print(ct)

for j in range(3):
    p.sendline(b'2')
    p.recvline()
    m = b'a'
    p.sendline(m)
    ct = p.recvline().decode('ascii')[:-1].split(' ')[-1]
    print(ct)
    for i in trange(10**6 + 1):
        seed = i
        # initial state (after first encryption)
        key = b''
        for i in range(8):
            key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
        key, ct1 = encrypt(m)
        if ct1 == ct:
            print(key)
            p.recvline()
            p.sendline(b'1')
            p.recvline()
            p.recvline()
            p.sendline(key)
            try:
                print(p.recvline())
                print(p.recvline())
                print(p.recvline())
            except:
                exit()
            break
```

Run the script to get the flag!  

    utflag{ok_you_are_either_really_lucky_or_you_solved_it_as_intended_yay}