---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/tuYBGri.png
points: 130
solves: 1401
tags: picoCTF crypto crypto/zlib crypto/Salsa20 crypto/brute-force
date: 1337-01-01
comments: false
---

Your goal is to find the flag. [compress_and_attack.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/compress_and_attack.py) `nc mercury.picoctf.net [port #]`  

---

We’re given a file, `compress_and_attack.py` and a service to connect to.
```py
#!/usr/bin/python3 -u


import zlib
from random import randint
import os
from Crypto.Cipher import Salsa20


flag = open("./flag").read()




def compress(text):
    return zlib.compress(bytes(text.encode("utf-8")))


def encrypt(plaintext):
    secret = os.urandom(32)
    cipher = Salsa20.new(key=secret)
    return cipher.nonce + cipher.encrypt(plaintext)


def main():
    while True:
        usr_input = input("Enter your text to be encrypted: ")
        compressed_text = compress(flag + usr_input)
        encrypted = encrypt(compressed_text)
       
        nonce = encrypted[:8]
        encrypted_text =  encrypted[8:]
        print(nonce)
        print(encrypted_text)
        print(len(encrypted_text))


if __name__ == '__main__':
    main()
```



So, essentially, it seems like we’ve been given an encryption oracle. The encryption oracle appends our input to the flag, compresses it with zlib, encrypts the result, and returns it back to us.  

However, there’s something a bit suspicious about the code. Why is the oracle returning the length of the encrypted text back to us...?  

If you’re familiar with compression algorithms, you might quickly notice the trick at this point. For those of you who are not familiar, here’s a short explanation:  

>Compression algorithms like zlib or even the zip files you often download online are based around one thing – **redundancy**. For example, say we have `file.txt` which contains the following data:  
>
>`abcdefgabcdefgabcdefg`  
>
>Notice how we have a thrice repeated string of `abcdefg`? The idea of compression algorithms is to recognize that redundancy in the file and encode that information about the >redudancy instead of the entire data.  
>
>So that's the entire idea surrounding compression. If you’re interested in learning more about it, watch a YouTube video or, for zlib specifically, check out [Understanding zlib](https://www.euccas.me/zlib/).  

This immediately made me wonder – perhaps we can exploit this by adding redundant characters? If we add the same characters as in the flag, perhaps the length of the compressed string won’t change at all, while if we add different characters, it will!  

That sounds like a good lead, and we can test it later. Now what about the encryption algorithm, Salsa20. What does that do?
With a bit of Googling, I found out that Salsa20 was a stream cipher. For those unfamiliar, here’s a quick breakdown of what a stream cipher is through an example:  

The simplest example of a stream cipher is XOR encryption. Let’s say we have the following message, `this is a message`, and key, `coolkey`. In order to encrypt this, we’d repeat the key until it is the same length as the message.  

|t|h|i|s| |i|s| |a| |m|e|s|s|a|g|e|
|c|o|o|l|k|e|y|c|o|o|l|k|e|y|c|o|o|

Then, we’d iterate through the message bytes, taking the ASCII codes of a message byte and XORing it with the ASCII code of the key byte.  


|t|h|i|s| |i|s| |a| |m|e|s|s|a|g|e|
|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|⊕|
|c|o|o|l|k|e|y|c|o|o|l|k|e|y|c|o|o|


Our final encryption would then be the exact same length as the original message!  
So it seems like the encryption itself doesn’t actually change the length of the compressed message. Rather, the cipher is probably just so we can’t just decompress the message and get the flag that easily.  

So now we are ready to start testing our findings. I first created a program to test if our hypothesis about adding characters of the flag was correct:  
```py
import zlib
from Crypto.Cipher import Salsa20
import os


def encrypt(plaintext):
    secret = os.urandom(32)
    cipher = Salsa20.new(key=secret)
    return cipher.nonce + cipher.encrypt(plaintext)


def compress(text):
    return zlib.compress(bytes(text.encode("utf-8")))


posschars = []
for i in range(26):
        posschars.append(chr(ord('a') + i))
for i in range(26):
        posschars.append(chr(ord('A') + i))
for i in range(10):
        posschars.append(str(i))
posschars.append('{')
posschars.append('}')
posschars.append('_')


testflag = 'picoCTF{afhdoa_385yhLsjk_t4Sg6}'
add = ''
res = encrypt(compress(testflag + add))
print(len(res), res)
add = 'picoCTF{afh'
res = encrypt(compress(testflag + add))
print(len(res), res)
add = 'picoCTF{afc'
res = encrypt(compress(testflag + add))
print(len(res), res)
```

Changing the `add` string several times to different prefixes of the flag, I found that the length of the compressed and encrypted string increased when the next character was wrong and stayed the same when it was right.  

Aha! There’s our vulnerability. All that’s left is to create an exploit to brute force the characters and get the flag!  

```py
from pwn import *

posschars = []
for i in range(26):
        posschars.append(chr(ord('a') + i))
for i in range(26):
        posschars.append(chr(ord('A') + i))
for i in range(10):
        posschars.append(str(i))
posschars.append('{')
posschars.append('}')
posschars.append('_')


print(posschars)


payload = 'picoCTF{'
target = remote('mercury.picoctf.net', 29350)
target.recv()
target.sendline(payload)
target.recvline()
target.recvline()
maintain = int(target.recvline()[:-1].decode('utf-8'))
print(maintain)
target.close()


while(True):
        for c in posschars:
                send = payload + c
                send = send.encode()
                target = remote('mercury.picoctf.net', 29350)
                target.recv()
                target.sendline(send)
                target.recvline()
                target.recvline()
                length = int(target.recvline()[:-1].decode('utf-8'))
                target.close()
                if length == maintain:
                        payload += c
                        print(payload)
        if payload[-1] == '}':
                print('done')
                break


print(payload)
```

    picoCTF{sheriff_you_solved_the_crime}
