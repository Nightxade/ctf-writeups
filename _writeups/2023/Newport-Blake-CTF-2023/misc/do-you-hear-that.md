---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/704MMP5.png
points: 241
solves: 162
tags: misc forensics audio-forensics
date: 2023-12-4
comments: false
---

I'm not sure why, but when I look at this image I can hear some sort of faint sound. Do you hear it too?  

[help.png](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/misc/help.png)  

---

The challenge description suggests there may be an audio file stored in this PNG file.  

Let's run binwalk on the program. It shows something called a "TIFF" image file?  

Checking out the bytes around that offset shows two very suspicious strings, "RIFF" (at 0x8A24) and "WAVE". A quick google search informs us that this is a `.wav` file.  

Simply extracting the bytes with a hex editor like HxD gives us our `.wav` file. However, if you take a listen, the audio file seems to be utter nonsense.  

A common strategy with audio forensics, though, is to use a program like Audacity to check the **spectrogram** of the audio file and see if there's a hidden message. And indeed, a quick check gives us our flag!  

    nbctf{y0u_h4v3_s0m3_g00d_34rs}

<img src="https://i.imgur.com/knClIVI.png" alt="do you hear that? Flag Image" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  