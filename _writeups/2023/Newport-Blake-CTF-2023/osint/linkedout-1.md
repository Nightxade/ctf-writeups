---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/QWftkWG.png
points: 352
solves: 100
tags: Newport-Blake-CTF-2023 osint osint/hex
date: 2023-12-4
comments: false
---

I’ve just finished setting up Newport blakes LinkedIn! I hope I didn't give away too much personal information in my profile. Someone might even be able to find a flag hidden in there.  

---

After a bit of searching on Linkedin, I found that searching for `Newport ctf` returned a suspicious profile with an "experience" of `NBCTF`.  

Scrolling down his profile, I found the following project:  

    Flag Designer for Newport Blake CTF
    Jun 2023 - Present
    In charge of designing flags for newport blake's CTF. 
    Check out some of my work:
    https://imgur.com/a/pGwm2Mg

Checking out the link returns an image that has nbctf{fake_flag} but also a very odd title, i.e. `68747470733a2f2f696d6775722e636f6d2f612f734f7469345248`. Isn't that hex?  

A hex-to-ASCII converter returns another [imgur link](https://imgur.com/a/sOti4RH), this time with the flag!  

    nbctf{D1d_1_M4ke_4_G00d_Fl4g?}