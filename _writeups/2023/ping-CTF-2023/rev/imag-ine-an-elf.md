---
layout: writeup
category: ping-CTF-2023
chall_description:
points: 170
solves: 31
tags: rev lsb
date: 2023-12-11
comments: false
---

This is no ordinary reversing challenge! As the Christmas season is coming, we thought that a real elf would be a great addition to our team. Unfortunately, the image of the elf got completely smashed and we can't see anything. Can you help us recover the elf? Please DON'T confuse a leprechaun with an elf!  

[5a0201f6e1fc25a759a85e307a4dd9f4.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/ping-CTF-2023/5a0201f6e1fc25a759a85e307a4dd9f4.zip)  

---

We're given an image, `elf.png`:  

<img src="https://i.imgur.com/vBE4TAF.png" alt="elf.png" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

Seems like a lot of gibberish. I opened it in HxD, a hex editor, and tried searching for some common strings in ELF files like `libc` and `ELF`.  

Strangely, there were none, so it didn't seem like we needed to try to fix an ELF header. Despite it being rev, I decided I might as well check the image out with stegsolve.  

Flipping through the different planes, I found a very suspicious-looking image in green plane 0.  

<img src="https://i.imgur.com/UdNVRkz.png" alt="Green Plane 0 from stegsolve" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

I figured that maybe an ELF program had been hidden using LSB of the green bits. I did Data Extract of Green 0 and, voila! We have an ELF program.  

We can extract this ELF program and reverse this. I decompiled with [Dogbolt](https://dogbolt.org/). Here's the relevant code from the Hex-Rays decompilation:  

```cpp
unsigned __int64 __fastcall check_flag(const char *a1)
{
  int i; // [rsp+1Ch] [rbp-94h]
  int v3[34]; // [rsp+20h] [rbp-90h]
  unsigned __int64 v4; // [rsp+A8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( strlen(a1) == 34 )
  {
    v3[0] = 96;
    v3[1] = 4958;
    v3[2] = 94;
    v3[3] = 84;
    v3[4] = 107;
    v3[5] = 114;
    v3[6] = 33;
    v3[7] = 4866;
    v3[8] = 51;
    v3[9] = 108;
    v3[10] = 36;
    v3[11] = 4953;
    v3[12] = 84;
    v3[13] = 4968;
    v3[14] = 98;
    v3[15] = 0;
    v3[16] = 70;
    v3[17] = 4968;
    v3[18] = 103;
    v3[19] = 4868;
    v3[20] = 92;
    v3[21] = 95;
    v3[22] = 79;
    v3[23] = 4931;
    v3[24] = 88;
    v3[25] = 57;
    v3[26] = 68;
    v3[27] = 6;
    v3[28] = 79;
    v3[29] = 4933;
    v3[30] = 36;
    v3[31] = 4933;
    v3[32] = 35;
    v3[33] = 78;
    for ( i = 0; i <= 33; ++i )
    {
      if ( (i & 1) != 0 )
      {
        if ( i % 3 )
        {
          if ( i % 5 )
          {
            if ( (a1[i] ^ 0x1337) != v3[i] )
            {
LABEL_14:
              puts("Wrong!");
              return v4 - __readfsqword(0x28u);
            }
          }
          else if ( a1[i] + 5 != v3[i] )
          {
            goto LABEL_14;
          }
        }
        else if ( (char)(a1[i] ^ 0x33) != v3[i] )
        {
          goto LABEL_14;
        }
      }
      else if ( a1[i] - 16 != v3[i] )
      {
        goto LABEL_14;
      }
    }
    printf("Correct! The flag is: %s\n", a1);
  }
  else
  {
    puts("Wrong!");
  }
  return v4 - __readfsqword(0x28u);
}

//----- (00000000000014E3) ----------------------------------------------------
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter the flag: ");
  __isoc99_scanf("%s", v4);
  check_flag(v4);
  return 0;
}
```

Seems like a program that modifies bytes based on their index. This should be pretty easy to reverse:  

```py
v3 = [0] * 34
v3[0] = 96;
v3[1] = 4958;
v3[2] = 94;
v3[3] = 84;
v3[4] = 107;
v3[5] = 114;
v3[6] = 33;
v3[7] = 4866;
v3[8] = 51;
v3[9] = 108;
v3[10] = 36;
v3[11] = 4953;
v3[12] = 84;
v3[13] = 4968;
v3[14] = 98;
v3[15] = 0;
v3[16] = 70;
v3[17] = 4968;
v3[18] = 103;
v3[19] = 4868;
v3[20] = 92;
v3[21] = 95;
v3[22] = 79;
v3[23] = 4931;
v3[24] = 88;
v3[25] = 57;
v3[26] = 68;
v3[27] = 6;
v3[28] = 79;
v3[29] = 4933;
v3[30] = 36;
v3[31] = 4933;
v3[32] = 35;
v3[33] = 78;

for i in range(34):
    if (i & 1) == 0:
        print(chr(v3[i] + 16), end='')
        continue
    if i % 3 == 0:
        print(chr(v3[i] ^ 0x33), end='')
        continue
    if i % 5 == 0:
        print(chr(v3[i] - 5), end='')
        continue
    
    print(chr(v3[i] ^ 0x1337), end='')
```

Running the script gets us the flag!  

    ping{m15C_4nd_r3V_w3ll_th4T5_r4r3}