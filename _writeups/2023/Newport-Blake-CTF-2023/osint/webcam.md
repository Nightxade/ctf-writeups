---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/HYkgw1a.png
points: 429
solves: 56
tags: osint google-maps
date: 12-4-2023
comments: false
---

인터넷에서 웹캠을 잃어버렸습니다. 정확히 어디에 있는지 알려주실 수 있나요? Flag is the coordinates of the location truncated to three digits, wrapped in nbctf. Example: `nbctf{XX.XXX_XX.XXX}`

[images.zip](https://github.com/Nightxade/ctf-writeups/assets/CTFs/Newport-Blake-CTF-2023/osint/images.zip)  

---

We're given several images and asked to find the location of this webcam.  

After reverse image search returned nothing, I decided to try and search up the names of certain buildings.  

Using a korean writing [tool](https://www.drawkorean.com/), I was able to transcribe some of the korean names: 

    1.png:
    늘방앗간
    수정카메

    2.png:
    김내과의원
    옥이네포

At this point, there weren't any more special tricks. All that was left was to brute force each name and see what I could find with Google Street View.  

Eventually, after more than an hour spent on this challenge over two days (  *I hate OSINT sometimes >:(*  ), for the very first name from `1.png`, I found the following address.  

    142-9 Song-u-ri, Soheul-eup, Pocheon-si, Gyeonggi-do, South Korea  

Using Google Street View, I looked around for notable buildings, and quickly found the close left building of `2.png` (the one with a solar panel and three flags). After getting it wrong for 15 minutes because I didn't have the right flag format T^T I finally submitted the right flag!  

    nbctf{37.827_127.145}