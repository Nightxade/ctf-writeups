---
layout: writeup
category: Cyber-Cooperative-CTF-2023
chall_description:
points: 250
solves: 121
tags: crypto randcrack
date: 2023-12-19
comments: false
---

I heard about this [scam that let people rob some slot machines](https://www.wired.com/2017/02/russians-engineer-brilliant-slot-machine-cheat-casinos-no-fix/). Can you do it with this slot machine?  
`nc 0.cloud.chals.io 30309`  

[server.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Cyber-Cooperative-CTF-2023/crypto/server.py)  

---
Here's `server.py`:  

```py
#!/usr/bin/env python
import random


def check(f1, f2, f3):
    if f1[0] == f1[1] == f1[2]:
        return True, f1[0] + f1[1] + f1[2]

    if f2[0] == f2[1] == f2[2]:
        return True, f2[0] + f2[1] + f2[2]

    if f3[0] == f3[1] == f3[2]:
        return True, f3[0] + f3[1] + f3[2]

    if f1[0] == f2[1] == f3[2]:
        return True, f1[0] + f2[1] + f3[2]

    if f1[2] == f2[1] == f3[0]:
        return True, f1[2] + f2[1] + f3[0]

    return False, "###"


def rng():
    test = str(random.getrandbits(32))
    test = test.zfill(10)
    return test


def server():
    money = 1000
    print(
        """
   _____ __    ____  ___________
  / ___// /   / __ \/_  __/ ___/
  \__ \/ /   / / / / / /  \__ \\
 ___/ / /___/ /_/ / / /  ___/ /
/____/_____/\____/ /_/  /____/
    """
    )

    print(f"YOU HAVE {money} MONEY")
    print()
    print(f"YOU WIN FOR EVERY MATCHING HORIZONTAL OR DIAGONAL LINE")
    print(f"FOR EVERY WIN YOULL GET YOUR WAGER TIMES THE MULTIPLIER")
    print(f"MAKE IT TO 1,000,000 FOR A FLAG")

    while True:
        try:
            wager = int(input("WAGER? "))
        except:
            wager = 1

        if wager < 0:
            print("SORRY BUD WE'RE NOT A BANK")
            exit()

        money -= wager

        start = rng()

        r1 = start[0:3]
        r2 = start[3:6]
        r3 = start[6:9]
        multi = start[9]

        f1 = r1[2] + r2[2] + r3[2]
        f2 = r1[1] + r2[1] + r3[1]
        f3 = r1[0] + r2[0] + r3[0]

        print()
        print("=>", f1[0], f1[1], f1[2])
        print("=>", f2[0], f2[1], f2[2])
        print("=>", f3[0], f3[1], f3[2])
        print(f"MULTIPLIER={multi}")
        print()

        result, hit = check(f1, f2, f3)

        if result is True:
            print("WINNER!", hit)
            money += wager * int(multi)
        else:
            print("BETTER LUCK NEXT TIME")

        print(f"YOU HAVE {money} MONEY")

        if money <= 0:
            print("SORRY BUD YOU'RE OUT OF CASH")
            exit()
        if money >= 1000000:
            print("FLAG REDACTED")
            exit()


if __name__ == "__main__":
    server()
```

If you read the article provided, you'll notice they discuss how these people noticed "patterns" in the slot machines. This seems to be implying we need to create a random number generator breaker.  

Thankfully, smart people have already created tools to do exactly that. [randcrack](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiEmYuY9JKDAxUolSYFHcL5AkMQFnoECA0QAQ&url=https%3A%2F%2Fgithub.com%2Ftna0y%2FPython-random-module-cracker&usg=AOvVaw1KGlhLUwFuu1rT0W04cDdx&opi=89978449) is a great module for cracking Python's random module with the Mersenne Twister.  

However, in order to crack the random module, we first need to pass it 624 randomly generated 32 bit numbers. We can generate 624 numbers easily by just sending 624 wagers of $0. But how can we get the random numbers themselves?  

Well, if we run the `server.py` file locally, we can add some print statements here:  

```py
        start = rng()

        print(start)

        r1 = start[0:3]
        r2 = start[3:6]
        r3 = start[6:9]
        multi = start[9]

        print(r1, r2, r3, multi)

        f1 = r1[2] + r2[2] + r3[2]
        f2 = r1[1] + r2[1] + r3[1]
        f3 = r1[0] + r2[0] + r3[0]

        print(f1, f2, f3)
```

Running this might produce an output like this:

```py
4096564708
409 656 470 8
960 057 464

=> 9 6 0
=> 0 5 7
=> 4 6 4
MULTIPLIER=8
```

At this point, you should be able to clearly observe how to derive the random number from the server's output. Here is the order:  

```py
=> 3 6 9
=> 2 5 8
=> 1 4 7
MULTIPLIER=10
```

Therefore, we can construct the random number from the output and pass that to RandCrack. Here's the implementation of that:  

```py
from randcrack import RandCrack
from pwn import *

p = remote('0.cloud.chals.io',30309)
print(p.recvuntil(b'WAGER? ').decode('ascii'))

rc = RandCrack()

for i in range(624):
    if i % 25 == 0: print(i)
    p.sendline(b'0')
    res = p.recvuntil(b'WAGER? ').decode('ascii').split('\n')
    f1 = res[1][3:].replace(' ','')
    f2 = res[2][3:].replace(' ','')
    f3 = res[3][3:].replace(' ','')
    mult = res[4][-1]

    #print(f1, f2, f3, mult)

    x = ''
    for i in range(3):
        x += f3[i]
        x += f2[i]
        x += f1[i]
    x += mult
    #print(x)
    x = int(x)
    rc.submit(x)
```

Now all we have to do is predict the result of each slot machine round, betting 0 on losing rounds and going all in on winning rounds. Here is the full implementation of the program:  

```py
def check(f1, f2, f3):
    if f1[0] == f1[1] == f1[2]:
        return True, f1[0] + f1[1] + f1[2]

    if f2[0] == f2[1] == f2[2]:
        return True, f2[0] + f2[1] + f2[2]

    if f3[0] == f3[1] == f3[2]:
        return True, f3[0] + f3[1] + f3[2]

    if f1[0] == f2[1] == f3[2]:
        return True, f1[0] + f2[1] + f3[2]

    if f1[2] == f2[1] == f3[0]:
        return True, f1[2] + f2[1] + f3[0]

    return False, "###"

from randcrack import RandCrack
from pwn import *

p = remote('0.cloud.chals.io',30309)
print(p.recvuntil(b'WAGER? ').decode('ascii'))

rc = RandCrack()

for i in range(624):
    if i % 25 == 0: print(i)
    p.sendline(b'0')
    res = p.recvuntil(b'WAGER? ').decode('ascii').split('\n')
    f1 = res[1][3:].replace(' ','')
    f2 = res[2][3:].replace(' ','')
    f3 = res[3][3:].replace(' ','')
    mult = res[4][-1]

    #print(f1, f2, f3, mult)

    x = ''
    for i in range(3):
        x += f3[i]
        x += f2[i]
        x += f1[i]
    x += mult
    #print(x)
    x = int(x)
    rc.submit(x)

def rng_mod():
    test = str(rc.predict_getrandbits(32))
    test = test.zfill(10)
    return test

money = '1000'
while int(money) < 1000000:
    start = rng_mod()

    r1 = start[0:3]
    r2 = start[3:6]
    r3 = start[6:9]
    multi = start[9]

    f1 = r1[2] + r2[2] + r3[2]
    f2 = r1[1] + r2[1] + r3[1]
    f3 = r1[0] + r2[0] + r3[0]

    result, hit = check(f1, f2, f3)

    if result:
        p.sendline(money.encode())
        money = str(int(money) * int(multi))
    else:
        p.sendline(b'0')

    if int(money) >= 1000000:
        p.interactive()
        break

    res = p.recvuntil(b'WAGER? ', timeout=5).decode('ascii').split('\n')
    if result: print(res)
```

As a sidenote, `timeout=5` was necessary to not timeout on certain inputs and the if statement checking if the money was sufficient was also necessary to not get EOF with the connection.  

Run the script for about 30 seconds to get the flag!  

    flag{only_true_twisters_beat_the_house}