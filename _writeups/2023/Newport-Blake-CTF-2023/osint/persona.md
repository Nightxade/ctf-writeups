---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/QZ50fmO.png
points: 261
solves: 150
tags: osint wayback-machine
date: 12-4-2023
comments: false
---

I have this username, can you help me uncover who it really is? They go by the name in2win9945 online.  

---

After testing out different social media I eventually found their [twitter profile](https://twitter.com/in2win9945)  

Monkeytype... maybe we can find that too? [here](https://monkeytype.com/profile/in2win9945)  

There's a link to a [blog](https://in2wintyping.blogspot.com/)  

Visiting his profile leads us to [another blog](https://kaspermellingencs.blogspot.com/2023/11/)  

[Post 1](https://kaspermellingencs.blogspot.com/2023/11/job-hunting.html) talks about him deleting stuff because of private information... maybe we can use the Internet Archive's Wayback Machine to find it?  

[Wayback Machine](https://web.archive.org/web/20231130062319/https://kaspermellingencs.blogspot.com/2023/11/job-hunting.html) finds our image, which shows his name! Kasper Mellingen. Search it up on [Linkedin](https://www.linkedin.com/search/results/all/?keywords=kasper%20mellingen&origin=GLOBAL_SEARCH_HEADER&sid=Sa6) and scroll through his posts to find the flag!  

    nbctf{o0p$_y0u_f0u$d_me}