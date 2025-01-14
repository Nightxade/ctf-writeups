---
layout: writeup
category: Iris-CTF-2024
chall_description:
points: 50
solves: 255
tags: osint osint/instagram
date: 2024-1-7
comments: false
---

Iris and her assistant are away on vacation. She left an audio message explaining how to get in touch with her assistant. See what you can learn about the assistant.  

Transcript: Hello, you’ve reached Iris Stein, head of the HR department! I’m currently away on vacation, please contact my assistant Michel. You can reach out to him at michelangelocorning0490@gmail.com. Have a good day and take care.  

[away-on-vacation.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/away-on-vacation.tar.gz)  

---

We're provided an audio file, but it is the same as the provided transcript.  

Emailing the provided gmail, I got a response that said something about Michelangelo being on social media and having an account about birds. Hm. Let's look it up on some sites.  

On Instagram, a simple search for Michelangelo Corning returns a profile! Scroll through its posts until you get the flag in the description of one of them: 

    irisctf{pub1ic_4cc0unt5_4r3_51tt1ng_duck5}