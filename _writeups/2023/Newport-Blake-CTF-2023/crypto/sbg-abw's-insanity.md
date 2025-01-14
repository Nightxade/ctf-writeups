---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/8fyVrrv.png
points: 432
solves: 54
tags: Newport-Blake-CTF-2023 crypto crypto/rsa
date: 2023-12-4
comments: false
---

"Skill Issue" - AnonymousBlueWhale  

[output.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/crypto/sbg-abw-output.txt) [chall.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/crypto/sbg-abw-chall.py)  

---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

We're given `chall.py` and `output.txt`. Here's `chall.py`:  

```py
from Crypto.Util.number import getPrime, bytes_to_long, isPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

m = bytes_to_long(b'we give you this as a gift!')

p = getPrime(1096)
q1 = getPrime(1096)
q2 = getPrime(1096)
n1 = p*q1
n2 = p*q2

e = 11

ct1 = pow(m,e,n1)
ct2 = pow(m,e,n2)

key = hashlib.sha256(long_to_bytes(q1)).digest()
cipher = AES.new(key, AES.MODE_ECB)
enc_flag = cipher.encrypt(pad(b"nbctf{[REDACTED]}", 16))

print("ct1 =", ct1)
print("ct2 =", ct2)
print("enc_flag =", enc_flag.hex())
```

So we're given a message, m, which is encrypted twice. In each encryption, the public exponent e is the same, 11. The modulus changes, but p actually remains a factor of both moduli. We receive both encrypted ciphertexts.  

If we can figure out p, we can then figure out q1, which will allow us to figure out the key for the AES encryption.  

Well, how can we figure out p? I immediately thought of taking the gcd. IF we can somehow find n1 and n2, we can take the gcd of the two numbers and get p.  

But how can we figure out n1 or n2? Take a look at the following:  

$$ct_1=m^e\;(mod\;n_1)$$  

$$ct_1=m^e+k_1n_1$$, $$k_1\in \mathbb{R}$$  
$$k_1n_1=ct_1-m^e$$  
Similarly, $$k_2n_2=ct_2-m^e$$  

Now, as you might notice, I didn't figure out what n1 and n2 were. Rather, I was able to figure out what some multiples of n1 and n2 were. Why does this work too?  

Well, the gcd of $$k_1n_1$$ and $$k_2n_2$$ is equivalent to $$gcd(k_1,k_2)\cdot gcd(n_1,n_2) = gcd(k_1,k_2)\cdot p$$  

Therefore, the gcd of $$k_1n_1$$ and $$k_2n_2$$ should result in some multiple of p. Most likely, this should be factorable, and the highest prime in its prime factorization will probably be p.  

Thus, we can create a simple Python implemenation to calculate this. And, as it turns out, fortunately for us, the gcd is actually prime, and thus it is itself p.  

```py
me = m**e

p = GCD(me - ct1, me - ct2)

assert isPrime(p)
```

Now, all we need to do is figure out q1. Well, given p, we can calculate that that $$\frac{k_1n_1}{p}=k_1q_1$$. Thus, it is suitable to calculate $$k_1q_1$$ and factorize that with a program or fast calculator like [this one](https://www.alpertron.com.ar/ECM.HTM). The highest prime of the factorization should be q1. Here is the factorization:  

```
2^2 × 29 × 269 × 4 338073 × 32 405327 × 28288 930455 976901 × 125986 153614 314299 × 603701 201822 386830 907144 477326 706640 694145 605732 107023 753674 808182 665696 931502 012989 218558 077472 289899 849882 120737 934821 898165 435847 435044 518846 871242 860227 586749 788240 998624 721376 490806 164324 545522 115137 075097 300642 534248 374378 375756 928831 273442 124872 283671 893345 317220 496457 140852 434166 575343 690062 190540 448032 738970 711476 061243
```

Therefore, we now know q1, and we can simply reverse the encryption code by getting the sha256 of q1 and using that as the key for an AES ECB decryption!  

```py
q1 = 603701201822386830907144477326706640694145605732107023753674808182665696931502012989218558077472289899849882120737934821898165435847435044518846871242860227586749788240998624721376490806164324545522115137075097300642534248374378375756928831273442124872283671893345317220496457140852434166575343690062190540448032738970711476061243

assert isPrime(q1)

key = hashlib.sha256(long_to_bytes(q1)).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(enc_flag)

print(flag)
```

    nbctf{c0ngr4ts_0n_F1nish1n9_Th3_3_P4rt3r!!!!}