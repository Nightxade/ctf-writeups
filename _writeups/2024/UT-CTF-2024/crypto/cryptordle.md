---
layout: writeup
category: UT-CTF-2024
chall_description:
points: 772
solves: 150
tags: crypto crypto/math
date: 2024-4-1
comments: false
---

Just guess the word in 6 tries. What do you mean it's hard?

By oops (former ISSS officer)

Officer in charge: jyu

`nc betta.utctf.live 7496`

[main-cryptordle.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UT-CTF-2024/main-cryptordle.py)  

---

We're provided a Python source file:  

```py
#!/usr/bin/env python3
import random

wordlist = open('/src/wordlist.txt', 'r').read().split('\n')

for word in wordlist:
    assert len(word) == 5
    for letter in word:
        assert letter in 'abcdefghijklmnopqrstuvwxyz'

for attempt in range(3):
    answer = random.choice(wordlist)
    num_guesses = 0
    while True:
        num_guesses += 1

        print("What's your guess?")
        guess = input().lower()

        assert len(guess) == 5
        for letter in guess:
            assert letter in 'abcdefghijklmnopqrstuvwxyz'

        if guess == answer:
            break

        response = 1
        for x in range(5):
            a = ord(guess[x]) - ord('a')
            b = ord(answer[x]) - ord('a')
            response = (response * (a-b)) % 31
        print(response)
    if num_guesses > 6:
        print("Sorry, you took more than 6 tries. No flag for you :(")
        exit()
    else:
        print("Good job! Onward...")

if num_guesses <= 6:
    print('Nice! You got it :) Have a flag:')
    flag = open('/src/flag.txt', 'r').read()
    print(flag)
else:
    print("Sorry, you took more than 6 tries. No flag for you :(")
```

To be honest, when I solved this challenge, I somehow completely missed the PYthon source file. idk how, I'm blind I guess. Managed to solve it anyways with some observation skills :)  

But regardless, the main observation here is that the number outputted for each guess is equivalent to the product of all the differences between the correct answer and the guess, character-by-character. Of course, this guess is equivalent to 0 if one of the characters is correct.  

With some testing by sending the following guesses:  

```
aaaaa
baaaa
caaaa
daaaa
etc. etc.
```

I realized that the guess changed by a fixed amount for each one-letter change. Knowing that a guess is 0 if one character is correct, we can very easily calculate the correct letter for that position given that fixed amount via the following program:  

```py
all_a = ?
change = ?
for i in range(1, 26):
    all_a -= change
    all_a %= 31
    if all_a == 0:
        print(chr(ord('a') + i))
```

Naturally, this lead me to consider sending the following guesses:  

```
aaaaa
baaaa
abaaa
aabaa
aaaba
aaaab
```

However, this would take up our 6 guesses, and we could only use 5 guesses before we needed to try to guess the actual word.  

But, since I didn't have the source file when I solved it (I assume there is a deterministic way to solve it with the source file), I simply cut the last string off, sending:  

```
aaaaa
baaaa
abaaa
aabaa
aaaba
```

And then, since the wordlist includes actual words (which I had figured out once I solved one manually with >6 guesses), I just guessed the last character :)  

Also, guessing was easier before because I actually did it when it was only 1 try.  

Here's the full implementation. Also, note that I ended up changing all a's to all z's in this script instead because having to solve 3 times in a row means a much higher likelihood that one word will contain an 'a'. If it does, that makes most of the guesses return 0, which we don't want!  

```py
from pwn import *
import solve2

p = remote('betta.utctf.live', 7496)

for i in range(3):
    p.recvline()
    p.sendline(b'b'*5)
    all_a = int(p.recvline().decode("ascii")[:-1])

    s = ''
    for j in range(4):
        p.recvline()
        payload = b'b'*j + b'c' + b'b'*(4-j)
        p.sendline(payload)
        x = int(p.recvline().decode("ascii")[:-1])
        if x == 0:
            print('0!!!')
            exit()
        res = solve2.s(all_a, (all_a - x) % 31)
        # print(res)
        s += res
    print(s)
    p.recvline()
    p.sendline(input().encode())

    print(p.recvline())

p.interactive()
```

solve2.py:  

```py
import string
def s(all_a, change):
    for i in range(1, 26):
        all_a -= change
        all_a %= 31
        if all_a == 0:
            return string.ascii_lowercase[(i + 1) % 26]
```

    utflag{sometimes_pure_guessing_is_the_strat}