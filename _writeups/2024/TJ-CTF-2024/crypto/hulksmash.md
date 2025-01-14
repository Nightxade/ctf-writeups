---
layout: writeup
category: TJ-CTF-2024
chall_description:
points: 229
solves: 23
tags: TJ-CTF-2024 crypto
date: 2024-5-19
comments: false
---

my friends password is keysmash.... :(... i got some of his old keysmashes tho.... he types kinda funny....

[output.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/hulksmash/output.txt)  
[keysmashes.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/hulksmash/keysmashes.txt)  
[main.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/hulksmash/main.py)  

---

Here's all the files:  

keysmashes.txt  

```yaml
fjdlska;sjfldka;
fldjs;akdka;flsj
d;flskajdlajf;sk
skflajd;a;djfksl
akd;sjflfja;dksl
flskd;ajs;fkajdl
fkald;sjaksldjf;
skd;ajflflajs;dk
fjs;dlakfkajd;sl
akfjdls;sldka;fj
fldjska;ajfkdls;
fjska;dla;slfjdk
s;fldjakdjfksla;
a;dkslfjdja;flsk
akf;djsldlf;skaj
sldjakf;a;fldksj
dlfka;sjskaldjf;
ska;djfls;akfldj
```

output.txt

```
ed05f1440f3ae5309a3125a91dfb0edef306e1a64d1c5f7d8cea88cdb7a0d7d66bb36860082a291138b48c5a6344c1ab
```

main.py

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = open("key.txt", "rb").read().strip()
flag = pad(open("flag.txt", "rb").read(), 16)
cipher = AES.new(key, AES.MODE_ECB)
open("output.txt", "w+").write(cipher.encrypt(flag).hex())
```

Basically, this challenge revolves entirely around using the keysmashes.txt file to figure out the key. I'm honestly a bit surprised this wasn't solved that much, but I guess a lot of people just missed the patterns. There are two patterns you need to see:  

- The letters of each line in keysmashes.txt alternate from one letter in "asdf" and one in "jkl;".  

- 2 of each byte of "asdfjkl;" is included in each line.  

And... that's it. Easy implementation from here on out:  

```py
# f = open('keysmashes.txt', 'r').read().split('\n')

# chars = 'asdfjkl;'
# for i in f:
#     counts = []
#     for c in chars:
#         counts.append(i.count(c))
#     print(counts)

import random
from tqdm import trange
from Crypto.Cipher import AES
from binascii import *

even = list('asdf'*2)
odd = list('jkl;'*2)

def key_gen():
    key = ''
    for i in range(16):
        if i % 2 == 0:
            key += even[i//2]
        else:
            key += odd[i//2]
    random.shuffle(even)
    random.shuffle(odd)
    return key.encode()

ct = unhexlify('ed05f1440f3ae5309a3125a91dfb0edef306e1a64d1c5f7d8cea88cdb7a0d7d66bb36860082a291138b48c5a6344c1ab')

for i in trange(479001600//2**7):
    key = key_gen()
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    try:
        print(pt.decode('ascii'))
    except:
        pass
```

    tjctf{low_entropy_keysmashuiyf8sa8uDYF987&^*&^}