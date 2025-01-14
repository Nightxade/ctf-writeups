---
layout: writeup
category: Jersey-CTF-IV-2024
chall_description:
points: 1000
solves: 1
tags: Jersey-CTF-IV-2024 osint
date: 2024-3-25
comments: false
---

- Okay, this is weird. They had a whole forum going.  
- There must be something worthwhile in there. We knew that something like this was happening, but I wasn't sure what we'd find.  
- If they were posting here someone probably slipped up along the way.  
- We need to identify where and when they met with the agent who slipped them the intel.  
- Build your case on these members and, from that, we may identify the mole.  
- Do not slow down. A rolling stone gathers no moss, so time to shed the green, noobie.  

Flag Format: jctf{mm-dd-yyyy_Venue-Name}  

Developed by: Cyb0rgSw0rd  

---

Check out the user g0ldenfalc0n7 on the [forums](https://drtomlei.xyz/forums). See the writeup for crypto/aces-aes for how to find the forum. g0ldenfalc0n7's user page also has a letterboxd link that includes several reviews.  

After chasing red herrings regarding Barbie movies and restaurant locations (that were discussed on the forum), our team finally searched up "the rugged lands". This returned some results about a song by the Wu-Tang Clan. Note that the Wu-Tang Clan were also mentioned on g0ldenfalc0n7's instagram posts (which we found in our investigation for osint/cyber-daddy).  

The rugged lands seemed to be about the "Mysterious Land of Shaolin". Checking out g0ldenfalc0n7's reviews on letterboxd, we can find a review on the movie "The 36th Chamber of Shaolin" [here](https://letterboxd.com/g0ldenfalc0n7/film/the-36th-chamber-of-shaolin/).  

Take a look at this section of the review:  

```
Being a fan of Wu-Tang Clan, I couldn't resist writing about this. One of the best times I ever had watching this film was a few years back. I saw this movie years ago when RZA did a live scoring of it in DC. What a trip! Not only was this as good as every time I saw it in the past, but the live music created the perfect ambience and cover for discrete conversations about work. I still think fondly of this time, despite it really being about work. Could you even imagine seeing one of your favorite artists doing a live scoring for a film that inspired them and has had such a profound impact on your life at the same time? All while doing work you only dreamed about as a kid? Thinking on it, it still brings a smile to my face.
```

Hmm. Seems like we're looking for a past concert venue of the Wu-Tang Clan and RZA, who is part of the Wu-Tang clan, in D.C. You can quickly search up a way to find past concert venues of the Wu-Tang Clan -- I used concertarchives.org. Scrolling back through the years, I found a match on [this page](https://www.concertarchives.org/bands/wu-tang-clan--2?date=past&page=10#concert-table) that included "RZA / Wu-Tang Clan" and was in 2018, which seemed promising. It turns out, it was the right flag!  

    jctf{04-18-2018_Warner-Theatre}

### Thoughts
This OSINT challenge actually took a lot longer than this short writeup seems to indicate. Overall, I probably spent 1-2 hours working on this :(  