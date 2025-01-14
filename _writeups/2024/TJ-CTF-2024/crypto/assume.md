---
layout: writeup
category: TJ-CTF-2024
chall_description:
points: 154
solves: 57
tags: TJ-CTF-2024 crypto
date: 2024-5-19
comments: false
---

assume for the sake of contradiction that pet the catloe

[main.sage](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/assume/main.sage)  
[log.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/assume/log.txt)  

---

Here's the sage source:  

```py
import random
import ast
import sys

p = random_prime(2^64-1, False, 2^63)
print(p)
R = Integers(p)

def gen_rand_string(n):
    return "".join([chr(random.randint(65, 90)) for _ in range(n)])

g = mod(primitive_root(p), p)
target_str = open("flag.txt").readline()

#print(target_str)

open("target.txt","w+").write(target_str)

def send_msg(sender, recipient, content):
    print(f"{sender} {recipient} {content}")

for pos in range(len(target_str)):
    fixed_eve = gen_rand_string(1)
    for iter in range(20):
        a = random.randint(1, p-1)
        b = random.randint(1, p-1)
        send_msg("Alice", "Bob", g^a)
        send_msg("Bob", "Alice", b)
        send_msg("Bob", "Alice", g^b)
        if random.randint(1, 2) == 1:
            # interception occurs
            c = random.randint(1, p-1)
            send_msg("Alice", "Bob", fixed_eve)
            send_msg("Alice", "Bob", g^c)
        else:
            send_msg("Alice", "Bob", target_str[pos])
            send_msg("Alice", "Bob", g^(a * b))
        print()

def input_with_timeout(prompt, timeout):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().rstrip('\n')
    raise Exception


try:
    answer = input_with_timeout('', 20)
    try:
        answer = ast.literal_eval(answer)
        if target_str == answer:
            print(":o")
            print(flag)
        else:
            print("im upset")
    except Exception as e:
        print("im very upset")
except Exception as e:
    print("\nyou've let me down :(")

```

If you take a look a the following section, you might notice something strange:  

```py
for pos in range(len(target_str)):
    fixed_eve = gen_rand_string(1)
    for iter in range(20):
        a = random.randint(1, p-1)
        b = random.randint(1, p-1)
        send_msg("Alice", "Bob", g^a)
        send_msg("Bob", "Alice", b)
        send_msg("Bob", "Alice", g^b)
        if random.randint(1, 2) == 1:
            # interception occurs
            c = random.randint(1, p-1)
            send_msg("Alice", "Bob", fixed_eve)
            send_msg("Alice", "Bob", g^c)
        else:
            send_msg("Alice", "Bob", target_str[pos])
            send_msg("Alice", "Bob", g^(a * b))
        print()
```

So, 50% of the time, it will print the byte of the flag at that position, and otherwise, it will print a capital letter. So... the flag is probably just the non-capital letter bytes in sequence?  

The answer is yes. This is not a real crypto problem. Just go through the log.txt file and note the bytes that aren't capital letters to get the flag:  

    tjctf{legendary_legendre0xd5109ab3}