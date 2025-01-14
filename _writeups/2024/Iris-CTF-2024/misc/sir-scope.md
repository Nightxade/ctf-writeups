---
layout: writeup
category: Iris-CTF-2024
chall_description:
points: 280
solves: 70
tags: misc misc/brute-force
date: 2024-1-7
comments: false
---

This circuit used to write out the flag using an array of 8 LEDs, but the LEDs are all burnt out now.  
[sir-scope.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/sir-scope.tar.gz)  

---

This one was actually a relatively simple challenge. Although intimidating, the gist is this:  

- The yellow represents binary, with the higher states being 1 and the lower states being 0.  

- Longer sections represent strings of 0s or 1s, depending if its a high/low state. It can be pretty easily eye-balled.  

- The purple is basically a separator between characters. Additionally, it means that whatever yellow is directly above the purple does not count.  

- The blue is probably(?) hinting towards the idea that there were 8 binary digits in each character.  

- Each 8-bit binary string is actually the **reverse** of the correct binary

After realizing all of this through testing on the first few characters, I just spent ~20 minutes brute-forcing the flag using Photopea to make things easier and an online converter.

    irisctf{0sc1llosc0pes_r_gr8_t00ls_2_hav3}