---
layout: writeup
category: Jersey-CTF-IV-2024
chall_description:
points: 997
solves: 17
tags: Jersey-CTF-IV-2024 crypto crypto/ecc crypto/secp256k1 crypto/signature
date: 2024-3-25
comments: false
---

To prevent the RB from impersonating any communications coming from you to our team, we need to employ an extremely secure digital signature algorithm. One of the most secure signature algorithms out there is the one used for bitcoin and ehtereum. Using the same Elliptic Curve used for those cryptocurrency calculations, hash and send me the message "Establishing a Secure Connection... :)". You also needed to provide me with the signature so that I can verify what was sent. The private key and other needed information is included in the file attached. Good luck agent!  

Flag Format: jctf{hashedMessage, (r, s)}  

Developed by: thatLoganGuy  

[importantInfo](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Jersey-CTF-IV-2024/importantInfo)  

---

Doing a little bit of research on secp256k1, I found this code that conveniently implemented both hashing and signing on [this site](https://asecuritysite.com/sage/sage_04). I copied it over, inputted the provided k and d values in the importantInfo file, and then printed out the hashed message and the signature!  

Here's the final implementation in SageMath:  

```py
import hashlib

F = FiniteField(2**256-2**32-2**9 -2**8 - 2**7 - 2**6 - 2**4 - 1)
a  = 0
b  = 7
E  = EllipticCurve(F, [a, b])
G  = E((55066263022277343669578718895168534326250603453777594175500187360389116729240, 
32670510020758816978083085130507043184471273380659243275938904335757337482424))
n  = 115792089237316195423570985008687907852837564279074904382605163141518161494337
h  = 1
Fn = FiniteField(n)

def hashit(msg):	
	return Integer('0x' + hashlib.sha256(msg.encode()).hexdigest())

def keygen():
	d = randint(1, n - 1)
	Q = d * G
	return (Q, d)

def ecdsa_sign(d, m):
	r = 0
	s = 0
	while s == 0:
		k = 18549227558159405545704959828455330521347940195552729233417641071946733850760
		while r == 0:
			k = 18549227558159405545704959828455330521347940195552729233417641071946733850760
			Q = k * G
			(x1, y1) = Q.xy()
			r = Fn(x1)
		e = hashit(m)
		s = Fn(k) ^ (-1) * (e + d * r)
	return [e, (r, s)]

d = 85752879200026332776470151463649568914870763740738869194582948094216537381852
m = 'Establishing a Secure Connection... :)'
print(ecdsa_sign(d, m))
```

    jctf{92203552243314903564601756136392727305670902362574958506092449257750428695994, (42784428704930896814896284055412332781569391987226306258297947802774199755263, 99723013502393641250124885860099834181116092463181585132024741529004971627174)}