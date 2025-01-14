---
layout: writeup
category: Cyber-Cooperative-CTF-2023
chall_description:
points: 300
solves: 104
tags: rev rev/bytecode
date: 2023-12-19
comments: false
---

Our field agents extracted the disassembly for a function that we think generates a secret flag. But it doesn't look like any kind of disassembly we can recognize. Can you figure it out?  

[dis.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Cyber-Cooperative-CTF-2023/rev/dis.txt)  

---

We're given a .txt file. Here it is:  

```py
 20           0 LOAD_CONST               1 (36054)

 21           2 LOAD_CONST               2 (55674)

 22           4 LOAD_CONST               3 (30924)

 23           6 LOAD_CONST               4 (59454)

 24           8 LOAD_CONST               5 (53145)

 25          10 LOAD_CONST               6 (70425)

 26          12 LOAD_CONST               7 (72954)

 27          14 LOAD_CONST               8 (15984)

 28          16 LOAD_CONST               9 (97605)

 29          18 LOAD_CONST              10 (93024)

 30          20 LOAD_CONST              11 (74205)

 31          22 LOAD_CONST              12 (34515)

 32          24 LOAD_CONST              13 (91584)

 33          26 LOAD_CONST              13 (91584)

 34          28 LOAD_CONST              14 (95364)

 35          30 LOAD_CONST              13 (91584)

 36          32 LOAD_CONST               4 (59454)

 37          34 LOAD_CONST              10 (93024)

 38          36 LOAD_CONST              15 (38394)

 39          38 LOAD_CONST              16 (17235)

 40          40 LOAD_CONST              17 (11115)

 41          42 LOAD_CONST               7 (72954)

 42          44 LOAD_CONST               8 (15984)

 43          46 LOAD_CONST              13 (91584)

 44          48 LOAD_CONST              10 (93024)

 45          50 LOAD_CONST               8 (15984)

 46          52 LOAD_CONST              13 (91584)

 47          54 LOAD_CONST              10 (93024)

 48          56 LOAD_CONST               3 (30924)

 49          58 LOAD_CONST              10 (93024)

 50          60 LOAD_CONST              18 (78084)

 51          62 LOAD_CONST               3 (30924)

 52          64 LOAD_CONST              14 (95364)

 53          66 LOAD_CONST              13 (91584)

 54          68 LOAD_CONST               1 (36054)

 55          70 LOAD_CONST              11 (74205)

 56          72 LOAD_CONST               3 (30924)

 57          74 LOAD_CONST              18 (78084)

 58          76 LOAD_CONST              19 (13644)

 59          78 LOAD_CONST              10 (93024)

 60          80 LOAD_CONST              20 (99144)

 61          82 LOAD_CONST               3 (30924)

 62          84 LOAD_CONST              18 (78084)

 63          86 LOAD_CONST              13 (91584)

 64          88 LOAD_CONST              21 (99945)
             90 BUILD_LIST              45
             92 STORE_FAST               0 (n)

 67          94 SETUP_LOOP              82 (to 178)
             96 LOAD_GLOBAL              0 (enumerate)
             98 LOAD_FAST                0 (n)
            100 CALL_FUNCTION            1
            102 GET_ITER
        >>  104 FOR_ITER                70 (to 176)
            106 UNPACK_SEQUENCE          2
            108 STORE_FAST               1 (i)
            110 STORE_FAST               2 (x)

 68         112 LOAD_GLOBAL              1 (int)
            114 LOAD_GLOBAL              2 (str)
            116 LOAD_FAST                0 (n)
            118 LOAD_FAST                1 (i)
            120 BINARY_SUBSCR
            122 CALL_FUNCTION            1
            124 LOAD_CONST               0 (None)
            126 LOAD_CONST               0 (None)
            128 LOAD_CONST              26 (-1)
            130 BUILD_SLICE              3
            132 BINARY_SUBSCR
            134 CALL_FUNCTION            1
            136 LOAD_FAST                0 (n)
            138 LOAD_FAST                1 (i)
            140 STORE_SUBSCR

 69         142 LOAD_FAST                0 (n)
            144 LOAD_FAST                1 (i)
            146 DUP_TOP_TWO
            148 BINARY_SUBSCR
            150 LOAD_CONST              23 (999)
            152 INPLACE_SUBTRACT
            154 ROT_THREE
            156 STORE_SUBSCR

 70         158 LOAD_FAST                0 (n)
            160 LOAD_FAST                1 (i)
            162 DUP_TOP_TWO
            164 BINARY_SUBSCR
            166 LOAD_CONST              24 (432)
            168 INPLACE_FLOOR_DIVIDE
            170 ROT_THREE
            172 STORE_SUBSCR
            174 JUMP_ABSOLUTE          104
        >>  176 POP_BLOCK

 72     >>  178 LOAD_CONST              25 ('')
            180 STORE_FAST               3 (o)

 73         182 SETUP_LOOP              24 (to 208)
            184 LOAD_FAST                0 (n)
            186 GET_ITER
        >>  188 FOR_ITER                16 (to 206)
            190 STORE_FAST               4 (p)

 74         192 LOAD_FAST                3 (o)
            194 LOAD_GLOBAL              3 (chr)
            196 LOAD_FAST                4 (p)
            198 CALL_FUNCTION            1
            200 INPLACE_ADD
            202 STORE_FAST               3 (o)
            204 JUMP_ABSOLUTE          188
        >>  206 POP_BLOCK

 75     >>  208 LOAD_FAST                3 (o)
            210 RETURN_VALUE
```

If you're not aware of what this is, a quick search of one of the instructions immediately tells you that this is Python bytecode.  

I tried seraching for a way to compile bytecode to a source file, but came up empty. Hence, I had to just read the assembly. Using [this](https://docs.python.org/id/3.5/library/dis.html) helped me determine what all of the instructiosn did.  

There's really no way to explain it. I will just provide my comments, which should be sufficient at explaining what's happening. If you want to solve this yourself, be patient -- it may take several read-throughs to understand the bytecode.  

My comments:  
```py
 20           0 LOAD_CONST               1 (36054)

 21           2 LOAD_CONST               2 (55674)

 22           4 LOAD_CONST               3 (30924)

 23           6 LOAD_CONST               4 (59454)

 24           8 LOAD_CONST               5 (53145)

 25          10 LOAD_CONST               6 (70425)

 26          12 LOAD_CONST               7 (72954)

 27          14 LOAD_CONST               8 (15984)

 28          16 LOAD_CONST               9 (97605)

 29          18 LOAD_CONST              10 (93024)

 30          20 LOAD_CONST              11 (74205)

 31          22 LOAD_CONST              12 (34515)

 32          24 LOAD_CONST              13 (91584)

 33          26 LOAD_CONST              13 (91584)

 34          28 LOAD_CONST              14 (95364)

 35          30 LOAD_CONST              13 (91584)

 36          32 LOAD_CONST               4 (59454)

 37          34 LOAD_CONST              10 (93024)

 38          36 LOAD_CONST              15 (38394)

 39          38 LOAD_CONST              16 (17235)

 40          40 LOAD_CONST              17 (11115)

 41          42 LOAD_CONST               7 (72954)

 42          44 LOAD_CONST               8 (15984)

 43          46 LOAD_CONST              13 (91584)

 44          48 LOAD_CONST              10 (93024)

 45          50 LOAD_CONST               8 (15984)

 46          52 LOAD_CONST              13 (91584)

 47          54 LOAD_CONST              10 (93024)

 48          56 LOAD_CONST               3 (30924)

 49          58 LOAD_CONST              10 (93024)

 50          60 LOAD_CONST              18 (78084)

 51          62 LOAD_CONST               3 (30924)

 52          64 LOAD_CONST              14 (95364)

 53          66 LOAD_CONST              13 (91584)

 54          68 LOAD_CONST               1 (36054)

 55          70 LOAD_CONST              11 (74205)

 56          72 LOAD_CONST               3 (30924)

 57          74 LOAD_CONST              18 (78084)

 58          76 LOAD_CONST              19 (13644)

 59          78 LOAD_CONST              10 (93024)

 60          80 LOAD_CONST              20 (99144)

 61          82 LOAD_CONST               3 (30924)

 62          84 LOAD_CONST              18 (78084)

 63          86 LOAD_CONST              13 (91584)

 64          88 LOAD_CONST              21 (99945)
             90 BUILD_LIST              45 # list of above
             92 STORE_FAST               0 (n) # var[0] = list

 67          94 SETUP_LOOP              82 (to 178) # initialize loop
             96 LOAD_GLOBAL              0 (enumerate) # load enumerate function
             98 LOAD_FAST                0 (n) # load list
            100 CALL_FUNCTION            1 # call enumerate...?
            102 GET_ITER
        >>  104 FOR_ITER                70 (to 176) # start of actual looping, iterate through list
            106 UNPACK_SEQUENCE          2 # unpack for enumeration
            108 STORE_FAST               1 (i) # index
            110 STORE_FAST               2 (x) # value in list

 68         112 LOAD_GLOBAL              1 (int) # load int cast onto stack
            114 LOAD_GLOBAL              2 (str) # load str cast onto stack
            116 LOAD_FAST                0 (n) # push list onto stack
            118 LOAD_FAST                1 (i) # push index onto stack
            120 BINARY_SUBSCR # store list[i] at top of stack (TOS), replacing i
            122 CALL_FUNCTION            1 # call top of stack function --> cast to string
            124 LOAD_CONST               0 (None) # push onto stack
            126 LOAD_CONST               0 (None) # push onto stack
            128 LOAD_CONST              26 (-1) # push onto stack
            130 BUILD_SLICE              3 # build and push slice of first three items on stack, i.e. (None, None, -1) --> equivalent to range(start, stop, step)
            132 BINARY_SUBSCR # list[None:None:-1]...? --> reversed string
            134 CALL_FUNCTION            1 # cast to int
            136 LOAD_FAST                0 (n) # push list onto stack
            138 LOAD_FAST                1 (i) # push index onto stack
            140 STORE_SUBSCR # list[i] = number with digits backwards

# list[i] = list[i] - 999
 69         142 LOAD_FAST                0 (n) # push list onto stack
            144 LOAD_FAST                1 (i) # push index onto stack
            146 DUP_TOP_TWO # duplicate top two references on the stack (i, n)
            148 BINARY_SUBSCR # top of stack = list[i]
            150 LOAD_CONST              23 (999) # push 999 onto stack
            152 INPLACE_SUBTRACT # TOS = list[i] - 999
            154 ROT_THREE # stacK: TOS, TOS1, TOS2 --> TOS1, TOS2, TOS
            156 STORE_SUBSCR # TOS1[TOS] = TOS2

# list[i] = list[i]//432
 70         158 LOAD_FAST                0 (n) # push list onto stack
            160 LOAD_FAST                1 (i) # push index onto stack
            162 DUP_TOP_TWO # duplicate top two references on the stack (i, n)
            164 BINARY_SUBSCR # top of stack = list[i]
            166 LOAD_CONST              24 (432) # push 432 onto stack
            168 INPLACE_FLOOR_DIVIDE # TOS = TOS1//TOS = list[i]//432
            170 ROT_THREE # stacK: TOS, TOS1, TOS2 --> TOS1, TOS2, TOS
            172 STORE_SUBSCR # TOS1[TOS] = TOS2 --> list[i] = list[i]//432
            174 JUMP_ABSOLUTE          104 # return to beginning of loop
        >>  176 POP_BLOCK # pop loop block (end loop)

 72     >>  178 LOAD_CONST              25 ('') # push empty string to stack
            180 STORE_FAST               3 (o) # store '' to var[3]

 73         182 SETUP_LOOP              24 (to 208) # loop
            184 LOAD_FAST                0 (n) # push list to stack
            186 GET_ITER
        >>  188 FOR_ITER                16 (to 206) # actual start of loop
            190 STORE_FAST               4 (p) # store list[i] to var[4]

 74         192 LOAD_FAST                3 (o) # push var[3] to stack
            194 LOAD_GLOBAL              3 (chr) # load chr function
            196 LOAD_FAST                4 (p) # push index to stack
            198 CALL_FUNCTION            1 # call chr function on p
            200 INPLACE_ADD # add p to var[3]
            202 STORE_FAST               3 (o) # var[3] = o
            204 JUMP_ABSOLUTE          188 # return to loop start
        >>  206 POP_BLOCK

 75     >>  208 LOAD_FAST                3 (o) # push var[3] to top of stack
            210 RETURN_VALUE # return top of stack
```

Now that we've reversed the function, we can write a simple Python program to simulate the same steps and get the flag!  

```py
a = [36054,55674,30924,59454,53145,70425,72954,15984,97605,93024,74205,34515,91584,91584,95364,91584,59454,93024,38394,17235,11115,72954,15984,91584,93024,15984,91584,93024,30924,93024,78084,30924,95364,91584,36054,74205,30924,78084,13644,93024,99144,30924,78084,91584,99945]

for i in range(len(a)):
    s = str(a[i])
    s = s[::-1]
    a[i] = int(s)
    a[i] -= 999
    a[i] //= 432

print(a)

for i in a:
    print(chr(i), end='')
```

Running the script gets the flag:  

    flag{whos_running_python_on_a_mainframe_damn}