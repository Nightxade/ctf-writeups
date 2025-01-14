---
layout: writeup
category: Vishwa-CTF-2024
chall_description:
points: 300
solves: 116
tags: Vishwa-CTF-2024 crypto crypto/decoder crypto/enigma
date: 2024-3-3
comments: false
---

All tavern owners in Mondstadt are really worried because of the frequent thefts in the Dawn Winery cellars. The Adventurers’ Guild has decided to secure the cellar door passwords using a special cipher device. But the cipher device itself requires various specifications….which the guild decided to find out by touring the entire Teyvat.  

PS: The Guild started from the sands of Deshret then travelled through the forests of Sumeru and finally to the cherry blossoms of Inazuma  

Author: Amruta Patil  

(Website provided once challenge instance is started).  

---

The website has four different sections, each with corresponding images of various odd languages. Each section will disappear upon a correct submission, revealing the text behind it.  

We can search up decoders for the Teyvat, Deshret, Sumeru, and Inazuma languages, and match them to each corresponding section to decode, which were all located on dcode.fr. (Note that I figured out Teyvat for the first image by searching up "Mondstadt language" after only seeing three languages listed in the challenge description).  

Notably, on my computer, for some reason, several of the images were not showing. Hence, I turned to looking at the page's source code for the images. [view-source:https://ch691692156209.ch.eng.run/](view-source:https://ch691692156209.ch.eng.run/).  

Conveniently, I also found the background image of the website by clicking on 'styles.css', which revealed a file that could be found at [https://ch691692156209.ch.eng.run/img/GenshinNoticeBoard.png](https://ch691692156209.ch.eng.run/img/GenshinNoticeBoard.png). It did lead to a little bit of confusion regarding if this was the flag or not, but still turned out useful because some of the inputs are weird.  

Decoding for each returns:  

1: Teyvat  
    ENIGMA MTHREE  
    (Input "ENIGMA M3")  
2: Deshret  
    UKW C  
3: Sumeru  
    ROTORONE I P M  
    ROTORTWO IV A O  
    ROTORTHREE VI I N  
    (Absolutely no clue how to get the input right on this one -- the web trick saved me)  
4: Inazuma  
    VI SH WA CT FX  

Use an engima decoder like [this one](https://cryptii.com/pipes/enigma-machine) with the above values to get the flag!  

    VishwaCTF{beware_of_tone-deaf_bard}