---
layout: writeup
category: ping-CTF-2023
chall_description:
points: 50
solves: 145
tags: rev 
date: 2023-12-11
comments: false
---

Don't smoke zigarettes, kids!  

[e0d8bf8fdefc32df23a1c96f047c50fc.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/ping-CTF-2023/e0d8bf8fdefc32df23a1c96f047c50fc.zip)  

---

We're given an ELF binary. I decompiled with [Dogbolt](https://dogbolt.org/) and examined the Ghidra code. Here's the relevant part:  

```c
  do {
    if (uVar8 == 0x23) goto LAB_00202664;
    if (uVar8 < 0x23) {
      cVar1 = *(char *)((long)&local_58 + uVar8);
      switch(uVar8) {
      case 0:
      case 0x20:
        if (cVar1 != 'p') goto LAB_00202677;
        break;
      case 1:
        if (cVar1 != 'i') {
LAB_00202677:
          uVar12 = 7;
          pcVar16 = "Wrong!\n";
          do {
            local_78[0] = 1;
            sVar4 = FUN_00202714(local_78,pcVar16,uVar12);
            if (sVar4 != 0) {
LAB_002025e0:
              uVar12 = *(undefined8 *)(&DAT_002006c8 + (long)sVar4 * 0x10);
              uVar3 = *(undefined8 *)(&DAT_002006d0 + (long)sVar4 * 0x10);
              local_70[0] = 2;
              FUN_0020284a(&DAT_00207104);
              local_78[0] = 2;
              sVar4 = FUN_00202714(local_78,"error: {s}\n",7);
              if ((sVar4 == 0) &&
                 (sVar4 = FUN_0020291a(uVar12,uVar3,&DAT_002006a0,local_70), sVar4 == 0)) {
                local_58 = CONCAT44(local_58._4_4_,2);
                FUN_00202714(&local_58,"\n",1);
              }
              FUN_00202888(&DAT_00207104);
            }
            syscall();
LAB_00202664:
            uVar12 = 9;
            pcVar16 = "Correct!\n";
          } while( true );
        }
        break;
      case 2:
        if (cVar1 != 'n') goto LAB_00202677;
        break;
      case 3:
        if (cVar1 != 'g') goto LAB_00202677;
        break;
      case 4:
        if (cVar1 != '{') goto LAB_00202677;
        break;
      case 5:
        if (cVar1 != 'z') goto LAB_00202677;
        break;
      case 6:
      case 9:
        if (cVar1 != '1') goto LAB_00202677;
        break;
      case 7:
        if (cVar1 != 'G') goto LAB_00202677;
        break;
      default:
        if (cVar1 != '_') goto LAB_00202677;
        break;
      case 10:
        if (cVar1 != 'S') goto LAB_00202677;
        break;
      case 0xc:
        if (cVar1 != 'v') goto LAB_00202677;
        break;
      case 0xd:
      case 0x17:
        if (cVar1 != '3') goto LAB_00202677;
        break;
      case 0xe:
        if (cVar1 != 'R') goto LAB_00202677;
        break;
      case 0xf:
        if (cVar1 != 'Y') goto LAB_00202677;
        break;
      case 0x11:
        if (cVar1 != 'C') goto LAB_00202677;
        break;
      case 0x12:
        if (cVar1 != '0') goto LAB_00202677;
        break;
      case 0x13:
      case 0x1e:
        if (cVar1 != 'O') goto LAB_00202677;
        break;
      case 0x14:
      case 0x21:
        if (cVar1 != 'l') goto LAB_00202677;
        break;
      case 0x16:
      case 0x1f:
        if (cVar1 != '2') goto LAB_00202677;
        break;
      case 0x18:
        if (cVar1 != '4') goto LAB_00202677;
        break;
      case 0x19:
        if (cVar1 != 'm') goto LAB_00202677;
        break;
      case 0x1a:
      case 0x1c:
        if (cVar1 != 'K') goto LAB_00202677;
        break;
      case 0x1b:
      case 0x1d:
        if (cVar1 != 'I') goto LAB_00202677;
        break;
      case 0x22:
        if (cVar1 != '}') goto LAB_00202677;
      }
    }
    uVar8 = uVar8 + 1;
  } while( true );
```

Seems like it's just a switch statement checking the characters! Only thing to note is that cases that come consecutively, where one case doesn't have a break statement before the next one, run the same code. Knowing that, brute-forcing becomes trivial:  

```
0123456789abcdef0123456789abcdef0123456789abcdef
ping{z1G_1S_v3RY_C0Ol_234mKIKIO2pl}
```