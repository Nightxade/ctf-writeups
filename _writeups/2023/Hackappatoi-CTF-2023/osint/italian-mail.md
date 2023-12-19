---
layout: writeup
category: Hackappatoi-CTF-2023
chall_description: N/A
points: 50
solves: N/A
tags: osint google-maps
date: 2023-12-10
comments: false
---

Enzo Tommasi was a YouTube "superstar" in Italy. He went viral with this video initially and then with many others. Can you find out where he was in this epic clip?  

[Video](https://www.youtube.com/watch?v=rNta7FLxq8s&ab_channel=Team_demon_loba)  

Flag format: hctf{street_name_number}  

---

 I searched for `enzo tommasi posteitaliane`. The top result was [this](https://www.youtube.com/watch?v=0okWSROpPkM), which just seemed to be a longer video of it. In the description, I noticed the following:  

    Ecco enzo il barbone di ostia! :)

I have no knowledge of Italian, but I decided I might as well translate it. As it turns out, Enzo is apparently from Ostia, a commune of Italy. We also know that he was at Posteitaliane, presumably a post office building. Maybe we can just search all the post offices in Ostia and find the one that looks right?  

Eventually, I came across [here](https://www.google.com/maps/place/%22Poste+Italiane%22+post+office/@41.7318242,12.2907958,19.25z/data=!4m10!1m2!2m1!1sostia+poste+italiane!3m6!1s0x1325efd7b7c4f647:0x3141232819de3dbe!8m2!3d41.7317529!4d12.2911678!15sChRvc3RpYSBwb3N0ZSBpdGFsaWFuZSIDiAEBkgELcG9zdF9vZmZpY2XgAQA!16s%2Fg%2F1trrxz32?entry=ttu)  

The images look the same as the Posteitaliane in the background of the original video, and it has the same ramp -- this must be it!  

    hctf{Via_Ferdinando_Acton_44}