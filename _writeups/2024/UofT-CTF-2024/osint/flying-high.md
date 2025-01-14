---
layout: writeup
category: UofT-CTF-2024
chall_description:
points: 100
solves: 354
tags: UofT-CTF-2024 osint
date: 2024-1-15
comments: false
---

I'm trying to find a flight I took back in 2012. I forgot the airport and the plane, but I know it is the one with an orange/red logo on the right side of this photo I took. Can you help me identify it?  

The flag format is UofTCTF{AIRPORT_AIRLINE_AIRCRAFT}. AIRPORT is the 3 letter IATA code, AIRLINE is the name of the airline (dash-separated if required), and AIRCRAFT is the aircraft model and variant (omit manufacturer name). For example, UofTCTF{YYZ_Air-Canada_A320-200} or UofTCTF{YYZ_Delta_767-300}.  

Note: The aircraft variant should be of X00 format; ie. there may be models with XYZ-432, but the accepted variant will be XYZ-400.  

Author: windex  
[airplane.png](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2024/airplane.png)

---

Airport:  
- Logo of nearby hangar reads "novespace", which is an airline
- Searching up "novespace airport" returns a location. [Google Street View](https://www.google.com/maps/@44.8379971,-0.7159023,3a,75y,117.47h,90.51t/data=!3m6!1e1!3m4!1saVmTHmV70ry_RU8h71VabQ!2e0!7i13312!8i6656?entry=ttu) near the Novespace hangar shows the image!  
- The nearby airport is the Bordeaux-Mérignac Airport, with code BOD

Airline:  
- Search "ib airline" due to logo looking somewhat like an "ib"
- Check out this image:  [https://www.google.com/search?client=firefox-b-1-e&sca_esv=598255384&sxsrf=ACQVn0-tbdHKEfEboXMrsYkF3QBoNwXiuQ:1705193363471&q=ib+airline&tbm=isch&source=lnms&sa=X&ved=2ahUKEwjEw8-l1NuDAxVxlWoFHU8RB2gQ0pQJegQIFhAB&biw=1536&bih=713&dpr=1#imgrc=SjNortQZtQ5CiM](https://www.google.com/search?client=firefox-b-1-e&sca_esv=598255384&sxsrf=ACQVn0-tbdHKEfEboXMrsYkF3QBoNwXiuQ:1705193363471&q=ib+airline&tbm=isch&source=lnms&sa=X&ved=2ahUKEwjEw8-l1NuDAxVxlWoFHU8RB2gQ0pQJegQIFhAB&biw=1536&bih=713&dpr=1#imgrc=SjNortQZtQ5CiM)  
- Clicking on the Wikipedia link and scrolling down to the image, the caption reveals that it is the old logo of Iberia Airlines.

Airplane:  
- Searching up "Iberia aircraft", we can find [this site](https://www.airfleets.net/flottecie/Iberia.htm).  
- Once I reached this point, I decided to just brute force all possibilities, as I wasn't sure how to proceed otherwise.  

I eventually ended up with the flag:  

    UofTCTF{BOD_Iberia_A340-300}