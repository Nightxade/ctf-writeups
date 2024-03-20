---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 350
solves: 47
tags: crypto hash sha1 length-extension-attack
date: 2024-3-19
comments: false
---

Surely they got it right this time.  

`nc tagseries3.wolvctf.io 1337`  

[chal.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/crypto/tag-series-3/chal.py) 

---

We're provided a Python source file:  

```py
import sys
import os
from hashlib import sha1

MESSAGE = b"GET FILE: "
SECRET = os.urandom(1200)


def main():
    _sha1 = sha1()
    _sha1.update(SECRET)
    _sha1.update(MESSAGE)
    sys.stdout.write(_sha1.hexdigest() + '\n')
    sys.stdout.flush()
    _sha1 = sha1()
    command = sys.stdin.buffer.readline().strip()
    hash = sys.stdin.buffer.readline().strip()
    _sha1.update(SECRET)
    _sha1.update(command)
    if command.startswith(MESSAGE) and b"flag.txt" in command:
        if _sha1.hexdigest() == hash.decode():
            with open("flag.txt", "rb") as f:
                sys.stdout.buffer.write(f.read())


if __name__ == "__main__":
    main()

```

Here's what's happening:  

1. We are provided the SHA1 hash of (SECRET + MESSAGE), where SECRET is unknown, but its length is known, and MESSAGE is known.  
2. We are asked to provide a command and a SHA1 hash. The command must start with MESSAGE and end with "flag.txt".  
3. The SHA1 hash of (SECRET + command) is compared to the user's inputted SHA1 hash. If they are equivalent, we win!  

After a bit of research on how to acquire a hash of a message given a hash of a prefix of the message, I found out this was a length extension attack. The idea is simple. Basically, the nature of SHA1 means that the SHA1 hash of a message is essentially the current values of the internal state of the hash, once it reaches the end of the message. To extend the message, we can just do the SHA1 hash again but with the internal state set to the current hash. Note that, to get the actual message that corresponds to this hash, it's also necessary to pad the message correctly, according to how it would be padded in standard SHA1.  

With this, all you need to do is research some implementations of the attack. I actually figured this out really quickly, but because I (stupidly) used `p.recvrepeat(0.1)` instead of just `p.recvline()` to get the flag, I wasted ~30 more minutes trying to figure out why my attack wasn't working. Eventually, though, after I had found a length extension attack implementation from a previous CTF writeup (sidenote: searching up something followed by CTF is often a great way to find implementations of certain attacks!), I tried changing how I received the program's output, and was very annoyed at myself.  

Anyways, I followed the logic from [here](https://github.com/AdityaVallabh/ctf-write-ups/blob/master/34C3%20-%20JuniorsCTF/kim/kimSolve.py) in the kimSolve.py file. Note that the hlextend.py file originates from [here](https://github.com/stephenbradshaw/hlextend).  

This was my final solve:  

```py
from pwn import *
import hlextend

s = hlextend.new('sha1')

def main():
    p = remote('tagseries3.wolvctf.io', 1337)
    print(p.recvline().decode('ascii')[:-1])

    message = 'GET FILE: '
    injection = 'flag.txt'

    original_tag = p.recvline().decode('ascii')[:-1]
    print(original_tag)

    new_message = s.extend(injection.encode(), message.encode(), 1200, original_tag)
    print(new_message)
    new_hash = s.hexdigest()
    print(new_hash)

    p.sendline(new_message)
    p.sendline(new_hash.encode())
    print(p.recvline().decode('ascii'))

main()
```

Run the script to get the flag!  

    wctf{M4n_t4er3_mu5t_b3_4_bett3r_w4y}