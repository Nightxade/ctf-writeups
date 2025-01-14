---
layout: writeup
category: UofT-CTF-2024
chall_description:
points: 100
solves: 314
tags: UofT-CTF-2024 osint osint/iot osint/reverse-image-search
date: 2024-1-15
comments: false
---

See introduction for complete context.  

Part 2 - What company makes the processor for this device? [https://fccid.io/Q87-WRT54GV81/Internal-Photos/Internal-Photos-861588](https://fccid.io/Q87-WRT54GV81/Internal-Photos/Internal-Photos-861588). Submit the answer to port 6318.  

---

We're given several photos about the processor. After a bit of exploring, I ended up deciding to reverse image search the image of the processor. The second result was [this](http://en.techinfodepot.shoutwiki.com/wiki/Linksys_WRT54G_v8.0). In the sidebar underneath the picture of the router, it tells us the CPU is a Broadcom BCM5354, so our answer is Broadcom!  

```
printf 'Broadcom\n\0' | nc 35.225.17.48 6318
```

    {Processor_Recon}