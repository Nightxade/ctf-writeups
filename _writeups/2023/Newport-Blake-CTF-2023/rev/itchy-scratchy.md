---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/s0LPgDe.png
points: 464
solves: 32
tags: rev Scratch brute-force
date: 2023-12-4
comments: false
---

Yeah sorry, I couldn't resist. Use Turbowarp if you want.  

[itchyscratchy.sb3](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/rev/itchyscratchy.sb3)  

---

Head over to Turbowarp and load the Scratch file in. Let's take a look inside.  

Immediately, you can observe two sections of code. One in the sprite `aatrox` and one in the Backdrop.  

Here's the sprite's code:  

<img src="https://i.imgur.com/YA35m9M.png" alt="sprite code" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

And here's the backdrop's code:  

<img src="https://i.imgur.com/sRsYm5r.png" alt="backdrop code" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

Let's first take a look at the sprite code. Immediately, we observe that our first answer must be `isaac newton`.  
Following our answer, the letter #, i.e. the index (1-based index) of each letter of `answer` in `alpha` is added to `name`. (Take a look at the code itself if you're confused by the explanation). But wait... where are `alpha` and  `name`?  

Fortunately, I remembered from a while ago where lists were located in Scratch, and quickly navigated to the `Variables` section of the left-hand code blocks panel. There, I checked each of the lists and rearranged them on screen so they were all visible. `input` and `name` were initially empty, until I ran the program and put in `isaac newton`, which filled in `name` for me. I assumed these lists might be useful somehow, so I exported them all by right-clicking on each list and clicking `Export`.  

Now that the sprite's code is essentially finished, let's take a look at the backdrop's code.  

Immediately, we can observe that it is asking us to input a flag, as the answer should start with `nbctf{` and end with `}`.  

Then, we enter 2 for loops, one after the other.  

The first one adds the 1-based index of each letter of `answer` in `alpha` (not including the flag prefix and suffix) to `input`.  

The second loop seems to be where the main logic is happening. I simply reversed the code in Python at this point to figure out what it was doing:  

```py
enc = [902,764,141,454,207,51,532,1013,496,181,562,342]
alpha = ["z","v","t","w","r","c","a","5","7","n","4","9","u","2","b","y","1","j","d","q","o","6","g","0","k","s","x","f","i","8","p","e","l","m","h","3"]
name = [29,26,7,7,6,0,10,32,4,3,21,10]

for i in range(1, 13):
    j = ((i)**2 + name[i - 1]) % len(name) + 1
    rightside = enc[i - 1] - name[i - 1] * name[j - 1]

    print(f'inp[{i - 1}] * inp[{j - 1}] = {rightside}')
```

Basically, I just printed out what the program was testing. This actually created a system of equations as follows:  

```py
inp[0] * inp[6] = 612
inp[1] * inp[6] = 504
inp[2] * inp[4] = 99
inp[3] * inp[11] = 384
inp[4] * inp[7] = 15
inp[5] * inp[0] = 51
inp[6] * inp[11] = 432
inp[7] * inp[0] = 85
inp[8] * inp[1] = 392
inp[9] * inp[7] = 85
inp[10] * inp[10] = 121
inp[11] * inp[10] = 132
```

At this point, I immediately thought of z3. But, after failing to use z3 (I had never used it before), I realized I could probably pretty easily brute force this! Staring with the 2nd to last equation, it is trivial to brute force all the values:  

```py
inp[0] * inp[6] = 612   # inp[0] = 17
inp[1] * inp[6] = 504   # inp[1] = 14
inp[2] * inp[4] = 99    # inp[2] = 33
inp[3] * inp[11] = 384  # inp[3] = 32
inp[4] * inp[7] = 15    # inp[4] = 3
inp[5] * inp[0] = 51    # inp[5] = 3
inp[6] * inp[11] = 432  # inp[6] = 36
inp[7] * inp[0] = 85    # inp[7] = 5
inp[8] * inp[1] = 392   # inp[8] = 28
inp[9] * inp[7] = 85    # inp[9] = 17
inp[10] * inp[10] = 121 # inp[10] = 11
inp[11] * inp[10] = 132 # inp[11] = 12
```

Thus, knowing the values of `input`, it becomes trivial to reverse the first Scratch for loop to get the flag!  

```py
inp = [0] * 12
inp[0] = 17
inp[1] = 14
inp[2] = 33
inp[3] = 32
inp[4] = 3
inp[5] = 3
inp[6] = 36
inp[7] = 5
inp[8] = 28
inp[9] = 17
inp[10] = 11
inp[11] = 12

[print(alpha[i - 1], end='') for i in inp]
```

Wrap the result in `nbctf{}` to get:  

    nbctf{12lett3rf149}