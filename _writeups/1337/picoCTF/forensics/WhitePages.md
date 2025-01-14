---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/pLRnscS.png
points: 250
solves: 4165
tags: forensics forensics/unicode forensics/binary
date: 1337-01-01
comments: false
---

I stopped using YellowPages and moved onto WhitePages... but the page they gave me is all blank!  
[whitepages.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/whitepages.txt)

---

```xxd whitepages.txt``` shows a sequence of repeated hex strings, 0xe28083 and 0x20  
Printing the file in python shows that the file is composed of two characters, \u2003 (unicode 2003) and regular spaces (ascii 0x20).  

```py
f = open(‘whitepages.txt’, ‘r’)
print(f.read())
```

From here, have the intuition to guess that the file actually represents a binary string. Try both possibilities for which character represents 0 and which represents 1. Using \u2003 = 0 and 0x20 = 1, and decoding the binary string with this website using ASCII for the character encoding, the flag should be returned.  


```py
f = open('whitepages.txt', 'r')
text = f.read()

c1 = '\u2003'
c2 =  ' '
bin = ''

for c in text:
        if c == c1:
                bin += '0'
        elif c == c2:
                bin += '1'
        else:
                print("something went wrong")
print(bin)
```
>  
>picoCTF  
>  
>SEE PUBLIC RECORDS & BACKGROUND REPORT  
>5000 Forbes Ave, Pittsburgh, PA 15213  
>**picoCTF{not_all_spaces_are_created_equal_3e2423081df9adab2a9d96afda4cfad6}**  
>  