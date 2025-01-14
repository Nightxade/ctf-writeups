---
layout: writeup
category: Hackappatoi-CTF-2023
chall_description:
points: 50
solves: N/A
tags: Hackappatoi-CTF-2023 rev rev/rot13
date: 2023-12-10
comments: false
---

The Cavaliere is returned. He is awake and he’s ready to unleash the apocalypse. Are you the chosen one? Solving this challenge will give you the access to the war against the four horsemen. Be ready.  

[thefourhorsemen](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Hackappatoi-CTF-2023/thefourhorsemen)

---

Let's head over to [Dogbolt](https://dogbolt.org/?id=f716f53f-44ad-42f7-8f53-60b52a5358ff#Hex-Rays=158) to decompile this.  

Immediately, in the Hex-Rays decompilation, I found this string:  

    upgs{lbher_ernql_gb_fgbc_gur_ncbpnylcfr}

Hm. Seems to be encrypted. Maybe it's just some ROT offset?  

Heading over to [https://www.dcode.fr/rot-cipher](https://www.dcode.fr/rot-cipher) and using ROT13 gives us the flag!  

	hctf{youre_ready_to_stop_the_apocalypse}