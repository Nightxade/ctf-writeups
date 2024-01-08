---
layout: writeup
category: Iris-CTF-2024
chall_description: N/A
points: 50
solves: 134
tags: network osint wifi
date: 2024-1-7
comments: false
---

While traveling over the holidays, I was doing some casual wardriving (as I often do). Can you use my capture to find where I went?  

Note: the flag is irisctf{the_location}, where the_location is the full name of my destination location, not the street address. For example, irisctf{Washington_Monument}. Note that the flag is not case sensitive.  

[wheres-skat.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/wheres-skat.tar.gz)  

Hint!  
If you're relying on Google Maps to get location names, be careful that it doesn't get lost in translation (for the non-Americans).  

---

This isn't much of a writeup, but the only thing I did was search up, on Google Maps or Google itself, several different SSIDs (wifi names) that looked like they could help me find the location. The most helpful searches were "Traxx Restaurant" and "Cilantro Union", which were both located nearby the Union Station in Los Angeles. "LAUS-Events" also helped with figuring this out. Combined with the constant reappearance of "Metro Wifi", I realized it was probably the Union Station.

    irisctf{los_angeles_union_station}

Sidenote: saying "full name" is very vague imo -- I didn't put los angeles until later.