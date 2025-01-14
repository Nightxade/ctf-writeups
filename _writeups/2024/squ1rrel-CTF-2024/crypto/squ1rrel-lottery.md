---
layout: writeup
category: squ1rrel-CTF-2024
chall_description:
points: 469
solves: 23
tags: squ1rrel-CTF-2024 crypto
date: 2024-4-28
comments: false
---

Welcome to the squ1rrel lottery! 9 winning numbers will be selected, and if any of your tickets share 3 numbers with the winning ticket you'll win a flag!

Hint: This is a math challenge

`nc 34.132.166.199 11112`

[squ1rrel-lottery.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/squ1rrel-CTF-2024/squ1rrel-lottery.py)  

---

Short (essentially a cheese) writeup.  

Here's the source:  

```py
import random

# user version
def input_lines():
    lines = []
    print("Welcome to the squ1rrel lottery! 9 winning numbers will be selected, and if any of your tickets share 3 numbers with the winning ticket you'll win! Win 1000 times in a row to win a flag")
    for i in range(1, 41):
        while True:
            line = input(f"Ticket {i}: ").strip()
            numbers = line.split()
            if len(numbers) != 9:
                print("Please enter 9 numbers")
                continue
            try:
                numbers = [int(num) for num in numbers]
                if not all(1 <= num <= 60 for num in numbers):
                    print("Numbers must be between 1 and 60")
                    continue
                lines.append(set(numbers))
                break
            except ValueError:
                print("Please enter only integers.")
    return lines


user_tickets = input_lines()
wincount = 0
for j in range(1000):
    winning_ticket = random.sample(range(1, 61), 9)

    win = False
    for i in user_tickets:
        if len(i.intersection(set(winning_ticket))) >= 3:
            print(f'Win {j}!')
            win = True
            wincount += 1
            break
    if not win:
        print("99 percent of gamblers quit just before they hit it big")
        break

if wincount == 1000:
    print("squ1rrelctf{test_flag}")

```

So, essentially the gist of the problem is that we're allowed to input 40 tickets, 9 numbers each between 1 and 60, inclusive. 1000 times in a row, we need at least one of our tickets to share at least 3 of the same numbers as the winning ticket.  

I believe the intended solution was some pigeonhole principle logic that involved actual math and thinking, but, I figured why not try to just evenly distribute the numbers?  

There are 40*9 = 360 inputs, so I put 6 of each number across the 40 tickets, ensuring that no one number is in the same ticket twice.  

My ticket generation fails like 70% of the time, but whenever it works it gets the flag so good enough `¯\_(ツ)_/¯`  

```py
from pwn import *
from random import *

sets = [[] for i in range(40)]
space = [9 for i in range(40)]
curr_indices = set()
for i in range(40):
    curr_indices.add(i)
next_indices = []
for i in range(1, 61):
    # print(space)
    indices = sample(list(curr_indices), 6 - len(next_indices)) + next_indices
    for j in indices:
        sets[j].append(i)
        space[j]-=1
        curr_indices.remove(j)
    for i in next_indices:
        curr_indices.add(i)
    next_indices = []
    if len(curr_indices) <= 6:
        for i in curr_indices:
            next_indices.append(i)
        for i in range(40):
            if space[i] > 0 and i not in next_indices: curr_indices.add(i)

# print('\n'.join(map(str, sets)))
for i in sets:
    assert len(set(i)) == len(i)
    assert len(i) == 9

# exit()

p = remote('34.132.166.199', 11112)
for i in range(40):
    # print(' '.join(map(str, sets[i])).split())
    p.sendlineafter(b': ', ' '.join(map(str, sets[i])).encode())
p.interactive()
```

    squ1rrelctf{your_prize_is_519225_squ1rrel_bucks}