---
layout: writeup
category: UT-CTF-2024
chall_description:
points: 100
solves: 305
tags: UT-CTF-2024 crypto crypto/caesar
date: 2024-4-1
comments: false
---

I've heard that everyone just uses dcode.fr to solve all of their crypto problems. Shameful, really.

This is really just a basic Caesar cipher, with a few extra random characters on either side of the flag. Dcode can handle that, right? >:)

The '{', '}', and '_' characters aren't part of the Caesar cipher, just a-z. As a reminder, all flags start with "utflag{".

By Khael (Malfuncti0nal on Discord).

[LoooongCaesarCipher.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UT-CTF-2024/LoooongCaesarCipher.txt)  

---

Caesar's Cipher is a type of encryption cipher that essentially shifts each character over by a specific offset. i.e., an offset of 1 means A -> B, B -> C, ..., Y -> Z, Z -> A.  

We could run every possible rotation number of Caesar's Cipher on the ciphertext, but, there's one problem. The ciphertext file is 977 kB, meaning that doing so will take a while.  

Instead, we can use an online Caesar's Cipher/ROT site like [this one](https://theblob.org/rot.cgi) to find all possible results for performing Caesar's cipher on "utflag", which is known to be the prefix for all flags. We can then Ctrl+F for each possible result in the txt file to find this string: "cbntio{zqx_lkwlm}", which decodes to the flag (using the same website):  

    utflag{rip_dcode}