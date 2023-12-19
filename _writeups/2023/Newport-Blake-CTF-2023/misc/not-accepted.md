---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/geENRkL.png
points: 365
solves: 93
tags: misc codeforces
date: 2023-12-4
comments: false
---

I can't seem to pass this problem... can you help me? https://codeforces.com/contestInvitation/9cf6e56adf19ecb8e5dd7af8a9c5bf5610c8e46e  

---

We're given an odd Codeforces problem:  

<img src="https://i.imgur.com/zBzFf96.png" alt="not accepted Codeforces problem statement" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

Simply submitting a Python program of  

```py
print(5)
```

Solves the problem and gives us the first part of our flag: `nbctf{n1C3_`  

I tried to run `ls` to see if perhaps there were some hidden files in the system, but inadvertently got the next flag due to `Wrong output format`!  

`L_mY_V3rd1cTs}`  

A simpler program to get the above flag could be the following:  

```py
print(5)
print(5)
```

Eventually, I ended up trying to see if just printing 4, the actual answer to 2+2, would work. And to my surprise, it did!  

`y0U_90t_4l`

Therefore, our flag is:  

    nbctf{n1C3_y0U_90t_4lL_mY_V3rd1cTs}

Sidenote: this challenge is a little bit guessy, but then again, this is the misc category  