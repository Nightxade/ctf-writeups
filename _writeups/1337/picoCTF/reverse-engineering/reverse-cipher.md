---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/fijgEKe.png
points: 300
solves: 678
tags: picoCTF rev
date: 1337-01-01
comments: false
---

We have recovered a [binary](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/rev-cipher-rev) and a [text file](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/rev-cipher-rev_this). Can you reverse the flag.  

---

We're given an ELF binary `rev` and the encrypted flag `rev_this`. I used [Dogbolt](https://dogbolt.org/) to decompile. Here's the relevant code:  

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char ptr[23]; // [rsp+0h] [rbp-50h] BYREF
  char v5; // [rsp+17h] [rbp-39h]
  int v6; // [rsp+2Ch] [rbp-24h]
  FILE *v7; // [rsp+30h] [rbp-20h]
  FILE *stream; // [rsp+38h] [rbp-18h]
  int j; // [rsp+44h] [rbp-Ch]
  int i; // [rsp+48h] [rbp-8h]
  char v11; // [rsp+4Fh] [rbp-1h]

  stream = fopen("flag.txt", "r");
  v7 = fopen("rev_this", "a");
  if ( !stream )
    puts("No flag found, please make sure this is run on the server");
  if ( !v7 )
    puts("please run this on the server");
  v6 = fread(ptr, 0x18uLL, 1uLL, stream);
  if ( v6 <= 0 )
    exit(0);
  for ( i = 0; i <= 7; ++i )
  {
    v11 = ptr[i];
    fputc(v11, v7);
  }
  for ( j = 8; j <= 22; ++j )
  {
    v11 = ptr[j];
    if ( (j & 1) != 0 )
      v11 -= 2;
    else
      v11 += 5;
    fputc(v11, v7);
  }
  v11 = v5;
  fputc(v5, v7);
  fclose(v7);
  return fclose(stream);
}
```

Seems like it's just a simple encryption function that subtracts 2 from the character if it's at an odd index, and adds 5 to the character if it's at an even index. This should be pretty easily reversible!  

```py
s = "w1{1wq84fb<1>49" # encrypted flag within the {}
for i in range(8, 23):
        if (i & 1) != 0:
                print(chr(ord(s[i - 8]) + 2),end='')
        else:
                print(chr(ord(s[i - 8]) - 5),end='')
```

RUn the script to get the flag!  

    picoCTF{r3v3rs36ad73964}