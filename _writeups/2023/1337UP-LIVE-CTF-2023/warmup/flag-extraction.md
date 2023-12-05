---
layout: writeup
category: 1337UP-LIVE-CTF-2023
chall_description: https://i.imgur.com/fFTBKl5.png
points: 50
solves: 411
tags: warmup rar zip binwalk
date: 2023-11-27
comments: false
---
They told me I just need to extract flag but I don't know what that means?!
[flag.rar](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/1337UP-LIVE-CTF-2023/flag.rar)  

---

After extracting the first file with an online .rar extractor, I realized that it was probably just a bunch of nested compressions/zips, given that the next file was a .tar.xz file.  

The easiest solutions are to either use 7-Zip File Manager or just ```binwalk -eM flag.rar``` on Linux (```-e``` means extract, ```-M``` is basically recursive), which results in a final file, flag.gif.  

Use a hex editor and Ctrl+F for "INTIGRITI" or do ```grep "INTIGRITI" flag.gif``` on Linux to get the flag!  


    INTIGRITI{fl46_3x7r4c710n_c0mpl373}