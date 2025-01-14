---
layout: writeup
category: Jersey-CTF-IV-2024
chall_description:
points: 568
solves: 105
tags: Jersey-CTF-IV-2024 crypto crypto/rsa
date: 2024-3-25
comments: false
---

You have intercepted an encrypted message from the RB back to Dr. Tom!!!! The component values of Dr. Tom's public key are obviously readily available, but one of the components of his private keys was accidentally published as well! We've been eavesdropping on channels that Dr. Tom frequently uses, maybe these keys can be used to decrypt this traffic? The included files contain a message to decrypt, and the key components discussed.  

Developed by thatLoganGuy  

[publicKeys](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Jersey-CTF-IV-2024/publicKeys)  
[intercepted](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Jersey-CTF-IV-2024/intercepted)  

---

We're provided the ciphertext, n, e, and q. Simple RSA decryption -- search it up if you're a beginner.  


```py
from Crypto.Util.number import *

ct = b'w\n\xa3\xcb\xc2\xe1pjx\x867\x1cn\xc3\x9dB\x02?\xb2\x99\x8a\xb8-9;C\xa4\xb8\xfc\xc3\xca\xfe\x8e\x1e\xa1\xf5\xec[Rn&\xbb\x8b\n\xaf\x83^[P\xf9\x8c\xd5\x95~\xa7\xcb \xb0\x85Vfdu\x9d\xf5\xe4mXe\x95t\x96V\xe2\xcau\xe1\x90\x8cA/\xb1\xf3,\xa8\x04\xb9\xcf\x8fPXf\x0ffg\x8e>C\xc7\x12\xa3F\x04\x1a\t\xc2e\xdb\xc1\xf1iJ\x9e"+\x0b\x9d\xc2{\xe9\x1b\xbfN^\xb1\x14\xc3\xbfv\xeb\x90\xcd\xc7oi\xcc\x8fKQ\xdevy\x86$\x88\xca\xd6\xa9\xe3~\xd1g=ry\xf3\xcb\x85\xb7\xfa\xe1\xe0T\x8b\xcf\x18\xa0\xc3\x15\x15T\x82\xb1\xa16\xbcF\x06\xeb\x9d\xb5\xa4\x80$\x19f\x91\xb5\x8a\xe6\xe0\xf6Iu\x84\x87\xc6\xece\xf5\xfc\xd5D\xd6M\xe4knU\x06\xed\xa3\xdf^V\xc06h\xae\x9c\x89\x96V\xbe@\xf8m\xe0$\x11\x9d\xd9\xe2\xdb\x8an\xaa}\xce:\xa8C\x93\xb6O6\x07\xaf\xfb\x05\xb7}\xad\xdf\xd5%'
n = 17442167786986766235508280058577595032418346865356384314588411668992021895600868350218184780194110761373508781422091305225542546224481473153630944998702906444849200685696584928947432984107850030283893610570516934680203526010120917342029004968274580529974129621496912684782372265785658930593603142665659506699243072516516137946842936290278268697077045538529685782129547539858559544839323949738223228390505139321940994534861711115670206937761214670974876911762247915864144972967596892171732288160028157304811773245287483562194767483306442774467144670636599118796333785601743172345142463479403997891622078353449239584139
e = 65537
q = 5287605531078312817093699647404386356924677771068464930426961333492561825516192878006123785244929191711528060728030853752820877049331817571778425287562926236019883991325417165497210118975730500175398583896121555159133806789573964069837032915266548561424490397811232957782739002112133875199
p = n//q
phi = (p-1)*(q-1)
d = inverse(e, phi)

print(long_to_bytes(pow(bytes_to_long(ct), d, n)))
```

    jctf{HAHAHA I knew you would intercept this transmission. You may have won this round, but there are many more challenges for me to best you at}