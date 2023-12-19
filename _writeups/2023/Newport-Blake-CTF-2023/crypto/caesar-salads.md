---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/OQOvU8Q.png
points: 100
solves: 361
tags: crypto caesar
date: 2023-12-4
comments: false
---

Every CTF needs an introductory crypto. I found a roman emperor that made this super cool cipher. Can you decrypt this for me?  

[output.txt](https://github.com/Nightxade/ctf-writeups/assets/CTFs/Newport-Blake-CTF-2023/crypto/caesar-output.txt)  

---

We're given this ciphertext:  

	xlmdp{ryzo_drsc_gkcxd_dyy_rkbn_yp_k_cdkbd}

The challenge specifies it's about a Roman emperor. Simple caesar cipher [decoder](https://www.dcode.fr/caesar-cipher) should do the trick!  

    nbctf{hope_this_wasnt_too_hard_of_a_start}