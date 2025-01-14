---
layout: writeup
category: Cyber-Cooperative-CTF-2023
chall_description:
points: 200
solves: 142
tags: rev
date: 2023-12-19
comments: false
---

I need to make a key for this crackme for my homework. I just want to play video games, can you make a valid key for me? You can submit it here as the flag.

[easycrack](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Cyber-Cooperative-CTF-2023/rev/easycrack)  

---

We're given an ELF binary to reverse. I used [Dogbolt](https://dogbolt.org/) to decompile. Here is the relevant Hex-Rays decompilation:  

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+18h] [rbp-38h]
  int i; // [rsp+1Ch] [rbp-34h]
  char s[24]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v7; // [rsp+38h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  printf("Please enter a key: ");
  fgets(s, 13, _bss_start);
  v4 = 0;
  for ( i = 0; i < strlen(s); ++i )
    v4 += s[i];
  if ( v4 == 1337 && strlen(s) == 12 )
    printf("Nice key :) %s", s);
  else
    printf("Bad Key :( %s", s);
  return 0;
}
```

So, essentially, we just need all the ASCII codes of our key's characters to add up to 1337, and the length of our key to be 12. 1337 = 11 * 111 + 116, so I used that as the ASCII codes to generate my key:  

  ooooooooooot

I ran the program with my key, and it verified its validity, so I submitted it as the flag!  