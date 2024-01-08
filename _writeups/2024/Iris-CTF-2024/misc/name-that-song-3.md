---
layout: writeup
category: Iris-CTF-2024
chall_description: N/A
points: 435
solves: 38
tags: misc reverse-audio-search
date: 2024-1-7
comments: false
---

No more modarchive. Find the original title of this song which has been redacted from this file.  

Format: irisctf{never_gonna_give_you_up}  

Song titles and authors will be revealed at the end of competition.  
[namethatsong3.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/namethatsong3.tar.gz)    

---

We're given a file called `song1_redacted.kt`. Looking around with binwalk, strings, and xxd, I didn't find anything that gave the answer. Eventually, I ran `file song1_redacted.kt`, which said the following:  

```
song1_redacted.kt: Klystrack song, version 27, title \003e\377\030\001\336\003S\377`\001U\004D\377 \001\251\0048\377`\001I\005\037\377 \001x\005\027\377`\001\317\005\005\377 \001\232\006\311\376`\001\270\006\273\376 \001\001
```

Klystrack...? What's that? Also, the title is very clearly redacted, so no easy flag there.  

I searched up klystrack, and found that it was some sort of audio composer. I couldn't find any way to easily load the audio file, so I simply download klystrack and loaded in the audio file. It provided the option to export to .wav, so I did that too.  

At this point, I had listened to the audio file, and I realized that it didn't really sound like an audio file that was easy to search for. I tried using the mobile app Shazam, but no luck.  

Hence, I eventually turned to YouTube. I simply searched for `klystrack` and filtered for videos between 4-20 minutes, since the audio was 4:16. (There were no precise options). After a little bit of searching, I came across [this](https://www.youtube.com/watch?v=BTSfV-r_Qqc) video. And, conveniently enough, it turned out to be the correct audio!  

    irisctf{back_to_basics}

Sidenote: I explained this all relatively concisely, but in reality this took me quite a while to find :P