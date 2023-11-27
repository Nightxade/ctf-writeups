---
layout: writeup
category: 1337UP-LIVE-CTF-2023
chall_description: https://i.imgur.com/ApxDiNo.png
points: 100
solves: 201
tags: crypto rsa wiener
date: 2023-11-26
comments: false
---

Apparently this encryption is "really secure" and I don't need to worry about sharing the ciphertext, or even these values..  

n = 689061037339483636851744871564868379980061151991904073814057216873412583484720768694905841053416938972235588548525570270575285633894975913717130070544407480547826227398039831409929129742007101671851757453656032161443946817685708282221883187089692065998793742064551244403369599965441075497085384181772038720949  
e = 98161001623245946455371459972270637048947096740867123960987426843075734419854169415217693040603943985614577854750928453684840929755254248201161248375350238628917413291201125030514500977409961838501076015838508082749034318410808298025858181711613372870289482890074072555265382600388541381732534018133370862587  

[ciphertext](https://github.com/Nightxade/ctf-writeups/assets/CTFs/1337-UP-LIVE-CTF-2023/ciphertext)  

---

The values given and the problem name itself (whose acronym is cleverly RSA) implies that the encryption algorithm used is RSA. Except... that's a really large e value isn't it?   

Usually, it's more common to see e as 65537 or some other small number.  

If you're familiar with common RSA attacks, you might recognize this as Wiener's attack. Because e and d are modular inverses for a modulus of phi(n), i.e. Euler's Totient Function, when e is really large, d is usually pretty small! Therefore, it is possible to essentially figure out d with educated brute force.  

Simply using the owiener python module will allow you to easily decrypt the ciphertext and get the flag!  

    INTIGRITI{0r_n07_50_53cur3_m4yb3}

Here is the implementation:  
```py
def long_to_bytes(n):
    l = []
    x = 0
    off = 0
    while x != n:
        b = (n >> off) & 0xFF
        l.append( b )
        x = x | (b << off)
        off += 8
    l.reverse()
    return bytes(l)

def bytes_to_long(s):
    n = s[0]
    for b in (x for x in s[1:]):
        n = (n << 8) | b
    return n

import owiener

n = 689061037339483636851744871564868379980061151991904073814057216873412583484720768694905841053416938972235588548525570270575285633894975913717130070544407480547826227398039831409929129742007101671851757453656032161443946817685708282221883187089692065998793742064551244403369599965441075497085384181772038720949
e = 98161001623245946455371459972270637048947096740867123960987426843075734419854169415217693040603943985614577854750928453684840929755254248201161248375350238628917413291201125030514500977409961838501076015838508082749034318410808298025858181711613372870289482890074072555265382600388541381732534018133370862587
d = owiener.attack(e, n)

f = open('crypto/reallysecureapparently/ciphertext', 'rb').read()
f = bytes_to_long(f)
m = pow(f, d, n)
print(long_to_bytes(m))
```