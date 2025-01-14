---
layout: writeup
category: ping-CTF-2023
chall_description:
points: 50
solves: 59
tags: ping-CTF-2023 crypto crypto/caesar
date: 2023-12-11
comments: false
---

You've stumbled upon an encrypted message from the past, a mysterious code left behind by a figure from history. Your mission is to unravel the secrets hidden within. The code seems to be a form of ancient encryption, rumored to have been used by historical figures to secure their confidential messages.  

Attached to this challenge is an enigmatic image that may provide you with clues to crack the code. Delve into the realm of cryptic communication and use your skills to reveal the hidden message. The encryption method involves the manipulation of alphabetic characters, a technique that has intrigued cryptographers throughout history.  

Take a closer look at the accompanying image; it might hold the key to unlocking the encrypted text. Your goal is to decipher the hidden message and discover the wisdom or intrigue concealed within this historical enigma.  

Note: The image does not contain anything necessary for the solution.  

[2071dc8fe41830e3f171544fffc6128b.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/ping-CTF-2023/2071dc8fe41830e3f171544fffc6128b.zip)  

---

We are provided a ciphertext `encrypted_data.bin` and an image that seems to depict Julius Caesar. Caesar cipher perhaps?  

After playing around with several different ideas online for a good 15 minutes, I tried to just code my own shift in Python:  

(I must admit that I initially copied the ciphertext wrong and spent another 30 minutes trying to decode that T^T)  

```py
import binascii

s = binascii.unhexlify('2A2328212C161F28231016231E231016231D2310E2E6E0E1E4E0E5E510FCFD2E')

for i in range(128):
    news = b''
    for j in range(len(s)):
        news += ((s[j] + i) % 256).to_bytes(1, 'big')
    print(i, news)
```

This resulted in the suspicious string `yrwp{enwr_ermr_erlr_15/03/44_KL}`. This includes both numbers and letters, so I tried to put this in a ROT decoder for the alphanumeric alphabet. I used [this](https://www.dcode.fr/rot-cipher). Brute-force decryption very simply returned the flag!  

    ping{veni_vidi_vici_15/03/44_BC}

Admittedly, I should have gotten this much, much sooner than I did...  