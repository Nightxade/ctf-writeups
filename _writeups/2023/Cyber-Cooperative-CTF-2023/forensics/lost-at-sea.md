---
layout: writeup
category: Cyber-Cooperative-CTF-2023
chall_description: N/A
points: 100
solves: 278
tags: forensics wireshark
date: 2023-12-19
comments: false
---

I dropped my flag in the sea. Help me find it among the sharks!

[lost-at-sea.pcapng](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Cyber-Cooperative-CTF-2023/forensics/lost-at-sea.pcapng)  

---

We're given a very short .pcap file. Checking out one of the two HTTP packets' bytes should give you the flag!  

    flag{b4by_5h4rk_do0_d0o_d00_d0o_d0o_1n_th3_s34}