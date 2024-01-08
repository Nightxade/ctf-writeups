---
layout: writeup
category: Iris-CTF-2024
chall_description: N/A
points: 50
solves: 173
tags: osint instgram linkedin facebook
date: 2024-12-7
comments: false
---

Security questions can be solved by reconnaissance. The weakest link in security could be the people around you.  

[https://personal-breach-web.chal.irisc.tf/](https://personal-breach-web.chal.irisc.tf/)  

---

The website has 3 questions about Iris Stein:  

1. How old is Iris?  
2. What hospital was Iris born in?  
3. What company does Iris work for?  

Here is how to find each one:  

Age:  

- Elaina Stein, found on Iris's Instagram from Away on Vacation challenge. Post: https://www.instagram.com/p/C1qwh0Cuj5P/
- No Instagram
- Search on Facebook --> https://www.facebook.com/profile.php?id=61555040318052
- Birthdate listed on mother's Facebook as April 27th, 1996
- Therefore, she is now **27** years old  

Hospital:  

- Referenced as being ranked Best Maternity Hospital on mother's Facebook post  
- **Lenox Hill Hospital**  

Company:  

- Search Iris Stein, HR Department  
- LinkedIn profile that matches information and profile picture  
- **Mountain Peak Hiring Agency**  

Answers:  

- 27
- Lenox Hill Hospital
- Mountain Peak Hiring Agency

Flag:  

    irisctf{s0c1al_m3d1a_1s_an_1nf3cti0n}