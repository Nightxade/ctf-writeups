---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/I9lsaoZ.png
points: 420
solves: 62
tags: osint osint/hex
date: 2023-12-4
comments: false
---

Lets see your linkedin experience. There's another flag hidden somewhere, lets see if you can find it.  

---

Take a look at the url of the Linkedin page, [https://www.linkedin.com/in/newport-blake-ctf6e626374667b4431645f7930755f537030745f31743f7d/](https://www.linkedin.com/in/newport-blake-ctf6e626374667b4431645f7930755f537030745f31743f7d/)  

Doesn't that look suspiciously like a hex-encoded string? Throw that into a hex-to-ASCII converter to get your flag!  

    nbctf{D1d_y0u_Sp0t_1t?}