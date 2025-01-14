---
layout: writeup
category: ping-CTF-2023
chall_description:
points: 50
solves: 177
tags: web web/curl
date: 2023-12-11
comments: false
---

Watch the [PING CTF 2023 official trailer](https://www.youtube.com/watch?v=siZPvEGrtNY) and find the flag!  

---

Nothing on the video seemed to indicate a flag, and rememeber -- this is a web challenge.  

I decided to run `curl https://www.youtube.com/watch?v=siZPvEGrtNY | grep "ping{"` to see if there was anything in the source code, and quickly found the flag:  

    ping{hello_welcome_to_ping_ctf}