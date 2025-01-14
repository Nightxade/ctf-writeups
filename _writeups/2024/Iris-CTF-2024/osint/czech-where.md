---
layout: writeup
category: Iris-CTF-2024
chall_description:
points: 50
solves: 401
tags: osint osint/reverse-image-search
date: 2024-1-7
comments: false
---

Iris visited this cool shop a while back, but forgot where it was! What street is it on?  

[czech-where.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/czech-where.tar.gz)  

---

We're provided a single image. Using reverse image search on it, we find an exact match in [this post](http://tabiichigo.livedoor.biz/archives/51921024.html). It's in Japanese, so I simply used Google's automatic site translation to translate it to English. TL;DR, this is a blog about some visit in the Czech Republic.  

The blog itself provided some information, but I was unable to figure out the location from that. Hence, I decided to start reverse image searching some of the other images on the blog. [This](https://livedoor.blogimg.jp/rokitomo/imgs/6/1/61d5b9b2.jpg) one looked like a nice candidate, so I tried that.  

Immediately, I was presented with [this](https://commons.wikimedia.org/wiki/File:Ji%C5%99sk%C3%A1,_Pra%C5%BEsk%C3%BD_Hrad,_Hrad%C4%8Dany,_Praha,_Hlavn%C3%AD_M%C4%9Bsto_Praha,_%C4%8Cesk%C3%A1_Republika_(48792038977).jpg) wikimedia post. In the Summary section, it linked to a [source](https://geohack.toolforge.org/geohack.php?pagename=File:Ji%C5%99sk%C3%A1,_Pra%C5%BEsk%C3%BD_Hrad,_Hrad%C4%8Dany,_Praha,_Hlavn%C3%AD_M%C4%9Bsto_Praha,_%C4%8Cesk%C3%A1_Republika_(48792038977).jpg&params=050.091567_N_0014.403301_E_globe:Earth_type:camera_source:Flickr_&language=en).  

Clicking on the source gave us longitude and latitude coordinates. Perfect!  

I went to [Google Maps](https://www.google.com/maps/place/50%C2%B005'29.6%22N+14%C2%B024'11.9%22E/@50.0917429,14.4032919,20z/data=!4m4!3m3!8m2!3d50.0915556!4d14.4033056?entry=ttu) with the coordinates, and found that the images seemed to be from the street `Zlatá ulička u Daliborky`. Putting it in proper flag format returns the flag!  

    irisctf{zlata_ulicka_u_daliborky}