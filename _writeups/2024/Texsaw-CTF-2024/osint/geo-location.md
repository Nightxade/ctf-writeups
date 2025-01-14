---
layout: writeup
category: Texsaw-CTF-2024
chall_description:
points: 50
solves: -1
tags: Texsaw-CTF-2024 osint
date: 2024-3-25
comments: false
---

Find what street this picture was taken from.  

Format the flag as the following: The street name in all caps with the spaces replaced by underscores.  

Example: If the street was Bourbon Street the flag would be: texsaw{BOURBON_STREET}  

[picture.jpg](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Texsaw-CTF-2024/picture.jpg)  

---

Do a Google Reverse Image Search, drawing a rectangle area including only the most prominent building. Going to "Exact Matches", you'll find a building called TCC Legacy Kincaid. Searching it up will provide us an address. Move around the address in Google Street View until you find the Beal Bank sign, and thus the road it was taken from -- Legacy Dr!  

    texsaw{LEGACY_DRIVE}