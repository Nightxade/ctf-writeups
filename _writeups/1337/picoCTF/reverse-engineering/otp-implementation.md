---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/YyzALla.png
points: 300
solves: 678
tags: rev otp byte-by-byte
date: 1337-01-01
comments: false
---

Yay reversing! Relevant files: [otp](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/otp) [flag.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/otp-flag.txt)  

---

We're given an ELF binary `otp` and a `flag.txt` that contains the encrypted flag. Here's the relevant Hex-Rays decompilation by [Dogbolt](https://dogbolt.org/):  

```c
_BOOL8 __fastcall valid_char(char a1)
{
  if ( a1 > 47 && a1 <= 57 )
    return 1LL;
  return a1 > 96 && a1 <= 102;
}

//----- (00000000000007C0) ----------------------------------------------------
__int64 __fastcall jumble(char a1)
{
  char v2; // [rsp+0h] [rbp-4h]
  char v3; // [rsp+0h] [rbp-4h]

  v2 = a1;
  if ( a1 > 96 )
    v2 = a1 + 9;
  v3 = 2 * (v2 % 16);
  if ( v3 > 15 )
    ++v3;
  return (unsigned __int8)v3;
}

//----- (000000000000080E) ----------------------------------------------------
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // al
  char v5; // dl
  unsigned int v6; // eax
  int i; // [rsp+18h] [rbp-E8h]
  int j; // [rsp+1Ch] [rbp-E4h]
  char dest[112]; // [rsp+20h] [rbp-E0h] BYREF
  char s1[104]; // [rsp+90h] [rbp-70h] BYREF
  unsigned __int64 v11; // [rsp+F8h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  if ( argc > 1 )
  {
    strncpy(dest, argv[1], 0x64uLL);
    dest[100] = 0;
    for ( i = 0; valid_char(dest[i]); ++i )
    {
      if ( i )
      {
        v4 = jumble(dest[i]);
        v5 = s1[i - 1] + v4;
        v6 = (unsigned int)((s1[i - 1] + v4) >> 31) >> 28;
        s1[i] = ((v6 + v5) & 0xF) - v6;
      }
      else
      {
        s1[0] = (char)jumble(dest[0]) % 16;
      }
    }
    for ( j = 0; j < i; ++j )
      s1[j] += 97;
    if ( i == 100
      && !strncmp(
            s1,
            "adpjkoadapekldmpbjhjhbaghlfldbhjdalgnbeedheenfoeddabpmdnliokcahomdphbcleipfgibjdcgmjcmadaomiakpdjcni",
            0x64uLL) )
    {
      puts("You got the key, congrats! Now xor it with the flag!");
      return 0;
    }
    else
    {
      puts("Invalid key!");
      return 1;
    }
  }
  else
  {
    printf("USAGE: %s [KEY]\n", *argv);
    return 1;
  }
}
```

Seems like we're going through some sort of deterministic process to figure out if our key is correct. Notably, in the for loop containing most of this deterministic process, it only uses `si[i - 1]`, i.e. the previous byte that was just calculated, which, for the correct key value, would be the previous byte in the string they provided for us to compare with.  

Since we're only using the previous byte to determine our next byte, can't we just reverse this implementation and brute force the key byte-by-byte? Moreover, each byte of the key can only be a hex character, i.e. `0123456789abcdef`. This means that our brute force should only take maximum $$O(16 * N)$$. Since $$N=100$$, this should easily run in time! All that's left is to implement it! (and not mess it up like I did)  

```py
ct = "adpjkoadapekldmpbjhjhbaghlfldbhjdalgnbeedheenfoeddabpmdnliokcahomdphbcleipfgibjdcgmjcmadaomiakpdjcni"

def jumble(c):
        c = ord(c)
        v2 = c
        if c > 96:
                v2 = c + 9
        v3 = 2 * (v2 % 16)
        if v3 > 15:
                v3 += 1
        return v3


posschars = "0123456789abcdef"
key = ''
for i in range(0, len(ct)):
        worked = False
        for c in posschars:
                if i == 0:
                        if jumble(c) == ord(ct[i]) - 97:
                                key += c
                                print(c, end='')
                                worked = True
                                break
                        continue
                v4 = jumble(c)
                v5 = ord(ct[i - 1]) - 97 + v4
                v6 = (v5 >> 31) >> 28
                if ord(ct[i]) - 97 == (((v6 + v5) & 0xF) - v6):
                        key += c
                        print(c, end='')
                        worked = True
                        break
        if not worked: print('-', end='')

flag = "790ce176acf7c2b277040687b23e185b2bb0d0fcc1939bf782db10c1210218dc4b2b3c931a5c2f04ad5aa711d04175920aa0"

def strxor(a, b):
        assert len(a) == len(b)
        res = ''
        for i in range(0, len(a), 2):
                bi = i % len(b)
                res += chr(int(a[i:i+2], 16) ^ int(b[i:i+2], 16))
        return res

print(key)
print(strxor(flag, key))
```

Running this script gets us the flag!  

    picoCTF{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_db877006}