---
layout: writeup
category: Cyber-Cooperative-CTF-2023
chall_description:
points: 200
solves: 153
tags: forenics lsb binwalk
date: 2023-12-19
comments: false
---

Someone in our company leaked some very sensitive information. We absolutely cannot let this stand.  

Thankfully our monitoring software intercepted the screenshot that was leaked. An old engineer of ours did write some kind of watermarking for screenshots but we have no idea how it works. Can you figure it out?  

[captured.png](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Cyber-Cooperative-CTF-2023/forensics/captured.png)  

---

Opening up stegsolve, I flipped through the panes and noticed something suspicious in the top of Plane 0 for each of Red, Green, and Blue. Thus, this is probably Least Signficant Bit Steganography!  

To extract the data, I did Data Extract --> Red 0, Blue 0, Green 0 --> Save Bin.  

In the preview of the data extract, I also noticed a `PK` file header. The `PK` file header typically denotes a zip file. Thus, I decided to run `binwalk -eM` to extract all files.  

This resulted in a flag.txt in the extracted files. `cat flag.txt` gives the flag!  

    flag{what_came_first_the_stego_or_the_watermark}