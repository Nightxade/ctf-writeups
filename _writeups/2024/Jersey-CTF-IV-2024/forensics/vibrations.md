---
layout: writeup
category: Jersey-CTF-IV-2024
chall_description:
points: 990
solves: 28
tags: forensics network wireshark tcp modbus
date: 2024-3-25
comments: false
---

While managing some of our thermal systems, we noticed unusual behavior. We collected the network traffic, see if you can find anything unusual.  

Developed by: Dan D  

[final.pcapng](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Jersey-CTF-IV-2024/final.pcapng)  

---

Follow TCP Stream --> Stream 1 --> Hex Dump  

Some bytes left out --> all the bytes after the "}" are filled into the missing byte places in sequential order.  

    jctf{I_rEllAy_H0p3_thi$_i$nt_a_p0ol_sy$t3m_aGa1n}