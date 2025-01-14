---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/iPsR4Lf.png
points: 476
solves: 22
tags: rev rev/maze
date: 2023-12-4
comments: false
---

Can you escape the sand-filled maze before it's too late?  

`nc chal.nbctf.com 30401`  

[sands](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/rev/sands)  

---

We're given an ELF binary, `sands`.  

I decompiled with [Dogbolt](https://dogbolt.org/?id=ee4be75b-a4f2-4ae6-b745-81735c7befb5#Hex-Rays=106) and looked at the Hex-Rays code.  

Here is the relevant code:  

```c
unsigned __int8 byte_404080[100] = {   46u,   35u,   35u,   35u,   46u,   46u,   46u,   46u,   46u,   35u,   46u,   46u,   35u,   83u,   46u,   35u,   35u,   46u,   46u,   35u,   35u,   46u,   83u,   35u,   46u,   35u,   83u,   83u,   46u,   35u,   35u,   46u,   46u,   35u,   46u,   35u,   46u,   46u,   35u,   35u,   46u,   83u,   46u,   35u,   46u,   35u,   46u,   83u,   83u,   46u,   46u,   35u,   35u,   35u,   46u,   35u,   46u,   83u,   46u,   46u,   46u,   46u,   46u,   35u,   46u,   35u,   46u,   46u,   46u,   83u,   35u,   35u,   46u,   35u,   46u,   35u,   35u,   35u,   35u,   46u,   46u,   83u,   46u,   83u,   46u,   35u,   46u,   46u,   83u,   46u,   46u,   46u,   83u,   46u,   46u,   35u,   76u,   83u,   46u,   46u };

unsigned __int64 sub_4011D6()
{
  FILE *stream; // [rsp+8h] [rbp-58h]
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v3; // [rsp+58h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  stream = fopen("flag.txt", "r");
  fgets(s, 64, stream);
  puts(s);
  fclose(stream);
  return v3 - __readfsqword(0x28u);
}

unsigned __int64 sub_401252()
{
  unsigned __int64 result; // rax
  int jj; // [rsp+0h] [rbp-10h]
  int ii; // [rsp+0h] [rbp-10h]
  int k; // [rsp+0h] [rbp-10h]
  int j; // [rsp+0h] [rbp-10h]
  int kk; // [rsp+4h] [rbp-Ch]
  int n; // [rsp+4h] [rbp-Ch]
  int m; // [rsp+4h] [rbp-Ch]
  int i; // [rsp+4h] [rbp-Ch]

  result = (unsigned int)(dword_4040E8 % 4);
  if ( (_DWORD)result == 3 )
  {
    for ( i = 9; i >= 0; --i )
    {
      for ( j = 0; j <= 9; ++j )
      {
        result = byte_404080[10 * j + i];
        if ( (_BYTE)result == 83 )
        {
          result = (unsigned int)j;
          if ( j >= 0 )
          {
            result = (unsigned int)(i + 1);
            if ( (result & 0x80000000) == 0LL )
            {
              result = (unsigned int)(i + 1);
              if ( (int)result <= 9 )
              {
                result = byte_404080[10 * j + 1 + i];
                if ( (_BYTE)result == 46 )
                {
                  byte_404080[10 * j + i] = 46;
                  result = (unsigned __int64)&byte_404080[10 * j + 1 + i];
                  *(_BYTE *)result = 83;
                }
              }
            }
          }
        }
      }
    }
  }
  else if ( (int)result <= 3 )
  {
    if ( (_DWORD)result == 2 )
    {
      for ( k = 0; k <= 9; ++k )
      {
        for ( m = 0; m <= 9; ++m )
        {
          result = byte_404080[10 * k + m];
          if ( (_BYTE)result == 83 )
          {
            result = (unsigned int)(k - 1);
            if ( (result & 0x80000000) == 0LL )
            {
              result = (unsigned int)(k - 1);
              if ( (int)result <= 9 )
              {
                result = (unsigned int)m;
                if ( m >= 0 )
                {
                  result = byte_404080[10 * k - 10 + m];
                  if ( (_BYTE)result == 46 )
                  {
                    byte_404080[10 * k + m] = 46;
                    result = (unsigned __int64)&byte_404080[10 * k - 10 + m];
                    *(_BYTE *)result = 83;
                  }
                }
              }
            }
          }
        }
      }
    }
    else if ( (_DWORD)result )
    {
      if ( (_DWORD)result == 1 )
      {
        for ( n = 0; n <= 9; ++n )
        {
          for ( ii = 0; ii <= 9; ++ii )
          {
            result = byte_404080[10 * ii + n];
            if ( (_BYTE)result == 83 )
            {
              result = (unsigned int)ii;
              if ( ii >= 0 )
              {
                result = (unsigned int)(n - 1);
                if ( (result & 0x80000000) == 0LL )
                {
                  result = (unsigned int)(n - 1);
                  if ( (int)result <= 9 )
                  {
                    result = byte_404080[10 * ii - 1 + n];
                    if ( (_BYTE)result == 46 )
                    {
                      byte_404080[10 * ii + n] = 46;
                      result = (unsigned __int64)&byte_404080[10 * ii - 1 + n];
                      *(_BYTE *)result = 83;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    else
    {
      for ( jj = 9; jj >= 0; --jj )
      {
        for ( kk = 0; kk <= 9; ++kk )
        {
          result = byte_404080[10 * jj + kk];
          if ( (_BYTE)result == 83 )
          {
            result = (unsigned int)(jj + 1);
            if ( (result & 0x80000000) == 0LL )
            {
              result = (unsigned int)(jj + 1);
              if ( (int)result <= 9 )
              {
                result = (unsigned int)kk;
                if ( kk >= 0 )
                {
                  result = byte_404080[10 * jj + 10 + kk];
                  if ( (_BYTE)result == 46 )
                  {
                    byte_404080[10 * jj + kk] = 46;
                    result = (unsigned __int64)&byte_404080[10 * jj + 10 + kk];
                    *(_BYTE *)result = 83;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return result;
}

unsigned __int64 __fastcall sub_401818(unsigned int a1, _DWORD *a2, unsigned int *a3)
{
  unsigned __int64 result; // rax

  result = a1;
  if ( (_BYTE)a1 == 119 )
  {
    result = (unsigned int)*a2;
    if ( !(_DWORD)result )
      return result;
    result = byte_404080[10 * *a2 - 10 + *a3];
    if ( (_BYTE)result == 35 )
      return result;
    result = byte_404080[10 * *a2 - 10 + *a3];
    if ( (_BYTE)result == 83 )
      return result;
    result = (unsigned __int64)a2;
    --*a2;
  }
  if ( (_BYTE)a1 == 97 )
  {
    result = *a3;
    if ( !(_DWORD)result )
      return result;
    result = byte_404080[10 * *a2 + *a3 - 1];
    if ( (_BYTE)result == 35 )
      return result;
    result = byte_404080[10 * *a2 + *a3 - 1];
    if ( (_BYTE)result == 83 )
      return result;
    result = (unsigned __int64)a3;
    --*a3;
  }
  if ( (_BYTE)a1 == 115 )
  {
    result = (unsigned int)*a2;
    if ( (_DWORD)result == 9 )
      return result;
    result = byte_404080[10 * *a2 + 10 + *a3];
    if ( (_BYTE)result == 35 )
      return result;
    result = byte_404080[10 * *a2 + 10 + *a3];
    if ( (_BYTE)result == 83 )
      return result;
    result = (unsigned __int64)a2;
    ++*a2;
  }
  if ( (_BYTE)a1 == 100 )
  {
    result = *a3;
    if ( (_DWORD)result != 9 )
    {
      result = byte_404080[10 * *a2 + *a3 + 1];
      if ( (_BYTE)result != 35 )
      {
        result = byte_404080[10 * *a2 + *a3 + 1];
        if ( (_BYTE)result != 83 )
        {
          result = (unsigned __int64)a3;
          ++*a3;
        }
      }
    }
  }
  return result;
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4; // [rsp+Fh] [rbp-11h]
  int v5; // [rsp+10h] [rbp-10h] BYREF
  unsigned int v6; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v5 = 0;
  v6 = 0;
  do
  {
    do
      v4 = getchar();
    while ( v4 == 10 );
    sub_401252();
    ++dword_4040E8;
    sub_401818(v4, &v5, &v6);
    if ( dword_4040E8 > 49 || byte_404080[10 * v5 + v6] == 83 )
    {
      puts("ssssssssss");
      return 1LL;
    }
  }
  while ( byte_404080[10 * v5 + v6] != 76 );
  sub_4011D6();
  return 0LL;
}
```

Wow... that's a lot. When I first saw this, I was pretty intimidated by the entire thing, especially by `sub_401252()`.  

Let's try and break this down step-by-step, even if it will take a long time.

First, `main()`.  

The main function seems to enter a while loop that loops until this byte array at index `[10 * v5 + v6]` is 76. Once the loop finishes, it calls `sub_4011D6()`, which itself prints the flag. Taking a look at the byte array, I noticed there was only one value of 76. So this is our win condition -- get to 76 in this byte array.  

In our while loop, we enter another while loop that seems to just get input into v4 until the input is no longer a new line, as 10 is the decimal code of `\n`.  

It then calls `sub401252()` with no parameters, and proceeds to increment `dword_4040E8`, which is presumably our input length control.  

It then calls `sub401818()` with parameters v4, v5, and v6. Notably, the addresses of v5 and v6 are passed to the function, meaning that v5 and v6 can be modified by this function.  

Finally, it checks if `dword_4040E8 > 49`, which likely indicates our maximum path length is 49, or if `byte_404080[10 * v5 + v6] == 83`, i.e. if the byte array at that index is 83. If either of these are true, we return 1, meaning we fail.  

So main is just the control for everything that happens. Let's move on to the other functions.  

Because `sub401252()` looked intimidating, I decided to take a look first at `sub_401818()`.  

Immediately, I noticeed that the function checked if a1 was one of w, a, s, or d. The classic movement controls. This function must be how we move through the maze.  

Reading the function, I realized a couple things.  

1. a2 and a3 must be in the range [0, 9], inclusive.

2. a2 and a3 are clearly two separate dimensions of the maze, given that we're always multiplying a2 by 10 and just adding a3. a2 is the row variable, while a3 is the column variable.

3. We can never move into a square containing 35 and 83. So it seems that 35 and 83 are the 'walls' of our maze, while 46 is our allowed path.  

We can reimplement this movement function in python:  

```py
a2 = 0
a3 = 0
def att(a1):
    global a2
    global a3

    result = a1
    if a1 == 119: # w
        result = a2
        if not result: # a2 >= 0
            return result
        result = barr[10 * (a2 - 1) + a3]
        if result == 35 or result == 83:
            return result
        result = a2
        a2 -= 1
    elif a1 == 97: # a
        result = a3
        if not result: # a3 >= 0
            return result
        result = barr[10 * a2 + a3 - 1]
        if result == 35 or result ==  83:
            return result
        result = a3
        a3 -= 1
    elif a1 == 115: # s
        result = a2
        if result == 9: # a2 <= 9
            return result
        result = barr[10 * (a2 + 1) + a3]
        if result == 35 or result ==  83:
            return result
        result = a2
        a2 += 1
    elif a1 == 100: # d
        result = a3
        if result == 9: # a3 <= 9
            return result
        result = barr[10 * a2 + a3 + 1]
        if result == 35 or result ==  83:
            return result
        result = a3
        a3 += 1
    return result
```

Note that a2 and a3 are the same as v5 and v6, respectively, and that I made them global so we can modify them in the function. Also note that `barr` is my byte array.  

At this point, I completely forgot about the shifting part of this problem and the other function, `sub401252()`. Don't ask me why I spent like 30 minutes to an hour trying to figure out how to navigate the static maze with BFS.  

Once I finally figured out I definitely had not implemented the other function, I decided to take a look at that.  

Immediately, I noticed that we were swapping `83`'s and `46`'s in the array. Moreover, it seemed to be happening in a cycle of 4, and shifting in a different direction every time. There wasn't much further analysis to be done, and I just had to take like 20 minutes to implement.  

```py
def shiftsands(a: int):
    global barr
    result = a % 4
    if result == 3:
        for i in range(9, -1, -1):
            for j in range(0, 9 + 1, 1):
                result = barr[10 * j + i]
                if result != 83:
                    continue
                result = j
                if j < 0:
                    continue
                result = i + 1
                if result & 0x80000000 != 0:
                    continue
                result = i + 1
                if result > 9:
                    continue
                result = barr[10 * j + 1 + i]
                if result != 46:
                    continue
                result = barr[10*j + i] = 46
                barr[10 * j + 1 + i] = 83
    elif result == 2:
        for k in range(0, 9 + 1, 1):
            for m in range(0, 9 + 1, 1):
                result = barr[10 * k + m]
                if result != 83:
                    continue
                result = k - 1
                if result & 0x80000000 != 0:
                    continue
                result = k - 1
                if result > 9:
                    continue
                result = m
                if m < 0:
                    continue
                result = barr[10 * (k - 1) + m]
                if result != 46:
                    continue
                barr[10 * k + m] = 46
                barr[10 * (k - 1) + m] = 83
    elif result == 1:
        for n in range(0, 9 + 1, 1):
            for ii in range(0, 9 + 1, 1):
                result = barr[10 * ii + n]
                if result != 83:
                    continue
                result = ii
                if result < 0:
                    continue
                result = n - 1
                if result & 0x80000000 != 0:
                    continue
                result = n - 1
                if result > 9:
                    continue
                result = barr[10 * ii - 1 + n]
                if result != 46:
                    continue
                barr[10 * ii + n] = 46
                barr[10 * ii - 1 + n] = 83
    else:
        for jj in range(9, -1, -1):
            for kk in range(0, 9 + 1, 1):
                result = barr[10 * jj + kk]
                if result != 83:
                    continue
                result = jj + 1
                if result & 0x80000000 != 0:
                    continue
                result = jj + 1
                if result > 9:
                    continue
                result = kk
                if kk < 0:
                    continue
                result = barr[10 * (jj + 1) + kk]
                if result != 46:
                    continue
                barr[10 * jj + kk] = 46
                barr[10 * (jj + 1) + kk] = 83
    return result
```

Once I had all of this (and fixed all my implementing errors), I realized I could probably just solve this by hand with some nice print formatting:  

```py
moves = ''
for a in range(49):
    shiftsands(a)
    
    print('--------------------------------')
    for i in range(len(barr)):
        if i == a2 * 10 + a3:
            print('X', end=' ')
        else:
            print(chr(barr[i]), end=' ')
        if i % 10 == 9:
            print('\n')
    print(f'{a2}, {a3}')

    move = input("> ")
    moves += move
    att(ord(move))

    if barr[10 * a2 + a3] == 83:
        print("sssssssss")
        break
    elif barr[10 * a2 + a3] == 76:
        print("Success!")
        break

print(moves)
```

During this final solving process, I also finally realized that the 35's were the walls and the 83's were little snakes moving around the maze.  

I was quickly able to solve the maze by hand and get the final move order of `sdssssaassddssddwwwwwwwwdddssssssdsdsssaaasa`.  

I connected to the service and sent the moves to get the flag!  

    nbctf{5lowly_5huffl3d_5wa110wing_54nd5}

As a sidenote, I definitely spent longer than I should have to solve this. If only I hadn't forgotten the other function existed D:  