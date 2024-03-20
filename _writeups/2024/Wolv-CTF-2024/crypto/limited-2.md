---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 152
solves: 71
tags: crypto random time
date: 2024-3-19
comments: false
---

I was AFK when the flag was being encrypted, can you help me get it back?  

[NY_chal_time.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/crypto/limited-2/NY_chal_time.py) 

---

We're provided a Python source:  

```py
import time
import random
import sys

if __name__ == '__main__':
    flag = input("Flag? > ").encode('utf-8')
    correct = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]
    if len(flag) != len(correct):
        print('Nope :(')
        sys.exit(1)
    if time.gmtime().tm_year >= 2024 or time.gmtime().tm_year < 2023:
        print('Nope :(')
        sys.exit(1)
    if time.gmtime().tm_yday != 365 and time.gmtime().tm_yday != 366:
        print('Nope :(')
        sys.exit(1)    
    for i in range(len(flag)):
        # Totally not right now
        time_current = int(time.time())
        random.seed(i+time_current)
        if correct[i] != flag[i] ^ random.getrandbits(8):
            print('Nope :(')
            sys.exit(1)
        time.sleep(random.randint(1, 60))
    print(flag)

```

Seems like a similar encryption scheme as last time, except it occurs at some specific time in a given range and there's some time.sleep() trickery going on. However, we can do a similar "smart" brute-force tactic as in Limited 1 by looping through all the possible times and checking if the prefix matches for one of the times.  

First, let's figure out our range of possible times. The year must be 2023, and the day must be 365 or 366, as indicated by the if statements. I initially thought this meant our range of times was limited to one day, since 2023 is not a leap year, but ended up including the 366th day too later on since the time was actually within this 366th day, interestingly enough.  

There are 86,400 seconds in a day, so 2 days makes that 172,800 days. Considering that our prefix is length 5, i.e. `wctf{`, and we have to check each byte individually, the total iterations comes to 864,400. This is only 5 orders of magnitude (i.e. 10^5), so our smart brute force should run in time.  

The only thing left is to figure out how to deal with the `time.sleep(random.randint(1, 60))` statement. What we can do here, instead of waiting 1-60 seconds every time this is called (which would obviously not run in time) is just to add `random.randint(1, 60)` to the time. Remember that, since the random.seed() is set every time it loops, this will be the same value as it would be in the actual encryption process, provided we have the correct initial time.  

After the smart brute force of the inital time, we can easily decrypt via the same process.  

```py
import time
import random

init_time = 1703980800 # get this number for 12/31/2023 at https://www.epochconverter.com/  
x = time.gmtime(init_time)
assert x.tm_year == 2023 and x.tm_yday == 365

correct = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]
prefix = 'wctf{'
t = -1
for i in range(init_time, init_time + 86400*2):
    works = True
    time_slept = 0
    for j in range(5):
        
        random.seed(i + j + time_slept)
        x = random.getrandbits(8)
        if correct[j] ^ x != ord(prefix[j]):
            works = False
            break
        
        time_slept += random.randint(1, 60)

    if works:
        t = i
        break

print(t)
time_slept = 0
for i in range(len(correct)):
    random.seed(t + i + time_slept)
    print(chr(correct[i] ^ random.getrandbits(8)),end='')
    time_slept += random.randint(1, 60)
```

Run the script to get the flag!  

    wctf{b4ll_dr0p}