---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 50
solves: 297
tags: pwn pwn/buffer-overflow
date: 2024-3-19
comments: false
---

Just a little baby pwn.
`nc babypwn.wolvctf.io 1337 `

[babypwn](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/babypwn)  
[babypwn.c](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/babypwn.c)  

---

We're provided a binary ELF and a C source file. Here's the source:  

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct __attribute__((__packed__)) data {
  char buff[32];
  int check;
};

void ignore(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
}

void get_flag(void)
{
  char flag[1024] = { 0 };
  FILE *fp = fopen("flag.txt", "r");
  fgets(flag, 1023, fp);
  printf(flag);
}

int main(void) 
{
  struct data name;
  ignore(); /* ignore this function */

  printf("What's your name?\n");
  fgets(name.buff, 64, stdin);
  sleep(2);
  printf("%s nice to meet you!\n", name.buff);
  sleep(2);
  printf("Binary exploitation is the best!\n");
  sleep(2);
  printf("Memory unsafe languages rely on coders to not make mistakes.\n");
  sleep(2);
  printf("But I don't worry, I write perfect code :)\n");
  sleep(2);

  if (name.check == 0x41414141) {
    get_flag();
  }

  return 0;
}

```

The struct data allocates 32 bytes for `buff` and 8 bytes for the int `check`. However, fgets reads in 64 bytes from the standard input into name.buff. Since `check` is after `buff` on the stack, we can simply perform a buffer overflow by sending 32 random bytes and then 4 bytes of `AAAA` to pass the check in the code (note that `A`'s ASCII code is 0x41).  

My input was `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`. Connect to the service and send the input to get the flag!  

    wctf{pwn_1s_th3_best_Categ0ry!}