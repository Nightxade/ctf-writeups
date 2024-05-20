---
layout: writeup
category: TJ-CTF-2024
chall_description:
points: 118
solves: 151
tags: crypto rsa wiener
date: 2024-5-19
comments: false
---

weird crypto hmmm

[a.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/weird-crypto/a.py)  
[output.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/weird-crypto/output.txt)  

---

Here's the Python source:  

```py
from math import lcm
from Crypto.Util.number import bytes_to_long, getPrime

with open('flag.txt', 'rb') as f:
    flag = bytes_to_long(f.read().strip())

oops = getPrime(20)
p1 = getPrime(512)
p2 = getPrime(512)

haha = (p1-1)*(p2-1)
crazy_number = pow(oops, -1, haha)
discord_mod = p1 * p2
hehe_secret = pow(flag, crazy_number, discord_mod)

print('admin =', discord_mod)
print('hehe_secret =', hehe_secret)
print('crazy number =', crazy_number)

```

Seems like it's just some implementation of RSA, let's rename the variables:  

```py
from math import lcm
from Crypto.Util.number import bytes_to_long, getPrime

with open('flag.txt', 'rb') as f:
    flag = bytes_to_long(f.read().strip())

d = getPrime(20)
p1 = getPrime(512)
p2 = getPrime(512)

phi = (p1-1)*(p2-1)
e = pow(d, -1, phi)
n = p1 * p2
ct = pow(flag, e, n)

print('admin =', n)
print('hehe_secret =', ct)
print('crazy number =', e)

```

So, essentially, it generates a 20-bit prime d that will be used as the private exponent. You can either brute-force this value (20 bits is small) or use Wiener's attack, a well-known attack against implementations of RSA with small private exponents. The Python owiener module essentially just provides us with the attack itself, so:   

```py
from Crypto.Util.number import *
import owiener

n = 115527789319991047725489235818351464993028412126352156293595566838475726455437233607597045733180526729630017323042204168151655259688176759042620103271351321127634573342826484117943690874998234854277777879701926505719709998116539185109829000375668558097546635835117245793477957255328281531908482325475746699343
ct = 10313360406806945962061388121732889879091144213622952631652830033549291457030908324247366447011281314834409468891636010186191788524395655522444948812334378330639344393086914411546459948482739784715070573110933928620269265241132766601148217497662982624793148613258672770168115838494270549212058890534015048102
e = 13961211722558497461053729553295150730315735881906397707707726108341912436868560366671282172656669633051752478713856363392549457910240506816698590171533093796488195641999706024628359906449130009380765013072711649857727561073714362762834741590645780746758372687127351218867865135874062716318840013648817769047
d = owiener.attack(e, n)

print(long_to_bytes(pow(ct, d, n)))
```

And we get our flag!  

    tjctf{congrats_on_rsa_e_djfkel2349!}