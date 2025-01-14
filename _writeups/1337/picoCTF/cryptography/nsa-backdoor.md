---
layout: writeup
category: picoCTF
chall_description:
points: 500
solves: 563
tags: crypto crypto/diffie-hellman crypto/rsa crypto/smooth-primes crypto/pollard-attack
date: 1337-01-01
comments: false
---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

I heard someone has been sneakily installing backdoors in open-source implementations of Diffie-Hellman... I wonder who it could be... ;)  

- [gen.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/nsa-backdoor-gen.py)  
- [output.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/nsa-backdoor-output.txt)  

---

We're given a source file and an output file. Here's `gen.py`:  

```py
#!/usr/bin/python

from binascii import hexlify
from gmpy2 import *
import math
import os
import sys

if sys.version_info < (3, 9):
    math.gcd = gcd
    math.lcm = lcm

_DEBUG = False

FLAG  = open('flag.txt').read().strip()
FLAG  = mpz(hexlify(FLAG.encode()), 16)
SEED  = mpz(hexlify(os.urandom(32)).decode(), 16)
STATE = random_state(SEED)

def get_prime(state, bits):
    return next_prime(mpz_urandomb(state, bits) | (1 << (bits - 1)))

def get_smooth_prime(state, bits, smoothness=16):
    p = mpz(2)
    p_factors = [p]
    while p.bit_length() < bits - 2 * smoothness:
        factor = get_prime(state, smoothness)
        p_factors.append(factor)
        p *= factor

    bitcnt = (bits - p.bit_length()) // 2

    while True:
        prime1 = get_prime(state, bitcnt)
        prime2 = get_prime(state, bitcnt)
        tmpp = p * prime1 * prime2
        if tmpp.bit_length() < bits:
            bitcnt += 1
            continue
        if tmpp.bit_length() > bits:
            bitcnt -= 1
            continue
        if is_prime(tmpp + 1):
            p_factors.append(prime1)
            p_factors.append(prime2)
            p = tmpp + 1
            break

    p_factors.sort()

    return (p, p_factors)

while True:
    p, p_factors = get_smooth_prime(STATE, 1024, 16)
    if len(p_factors) != len(set(p_factors)):
        continue
    # Smoothness should be different or some might encounter issues.
    q, q_factors = get_smooth_prime(STATE, 1024, 17)
    if len(q_factors) == len(set(q_factors)):
        factors = p_factors + q_factors
        break

if _DEBUG:
    import sys
    sys.stderr.write(f'p = {p.digits(16)}\n\n')
    sys.stderr.write(f'p_factors = [\n')
    for factor in p_factors:
        sys.stderr.write(f'    {factor.digits(16)},\n')
    sys.stderr.write(f']\n\n')

    sys.stderr.write(f'q = {q.digits(16)}\n\n')
    sys.stderr.write(f'q_factors = [\n')
    for factor in q_factors:
        sys.stderr.write(f'    {factor.digits(16)},\n')
    sys.stderr.write(f']\n\n')

n = p * q
c = pow(3, FLAG, n)

print(f'n = {n.digits(16)}')
print(f'c = {c.digits(16)}')
```

If you've already tried picoCTF Very Smooth, you might notice that `gen.py` looks almost exactly the same, except for the last few lines. In fact, since the smooth prime generation is exactly the same, we can very easily factor n with the same method. Check it out [here](https://nightxade.github.io/ctf-writeups/writeups/1337/picoCTF/cryptography/very-smooth.html). Here is the actual implementation of factoring:  

```py
from gmpy2 import gcd
from Crypto.Util.number import long_to_bytes

n = '905767d77c44a3239d3c9306fc84d3058a630ced36f307b6297e4894519cf0a36d669b5f3b40220231531015a798af04d5bdac63abc8d14c2e2163fb51988e21fed21f049ef91b86afbce4236be5da60bf5f9f0017661351a11ba2eb2a0a0d273b4c864781d46d54255061719fef02027c3fb53bfea9ce173331e9be49c241c92857dbe383e7b234e483b39548c0422caee93c132d5e0032940f69963feb6f0ba169187a0d8c76ca8754d0d24d438df3a96b847e40f9b9b078644018c8c7ad706fc3841b6115510243c1f3215723884440e8259103db2ee4da96f2397bd6548aab7327826ec345af43f498781c2a7d3da797976591a458d0d0b6ae33dbbe7325'
c = '197dc99317cf5d378be7ee49eb10f018b6467abe4c671447c7dbf0aad3a0c1005bbaa4ddeb4e52c79a9dee0632e4065a5d2d7f8d2171079c8fe9940093166d6e1ef34723f1e127a3245d746c5bfeedd21fccdd365c43517efdb885b0a01069a603139f2411bb88c30729fc1a85a1c49718f103d3730f4a58900e339cde4243ec1ae98798368b956be1b98997e56f1ad1766057346ccee4cdbdb3e7f16a2387d724ac8be54673f4abba53af16f3774b16378484235eaceb126a4b2e95b7fef78add7914353828c13df6d07bd0a838e7c09e88d2944f73e1d609001998e77b90f106d451072004e554c1b0c13b6cf5e0b43620d94039c45fb055e1263d54c6b82f'

n = int(n, 16)
c = int(c, 16)


# Pollard's attack
a = 2
B = 2**16
for i in range(2, B + 1):
        if i % 1000 == 999:
                print(i)
        a = pow(a, i, n)

        d = gcd(a - 1, n)

        if 1 < d and d <n:
                print('Prime Factorization of', n)
                print('(', d, ',', n//d, ')')

# p = 171737105398642886952850023587557331022400498172400869641426551638589932026649898397876829050302065185503267016434202639701993923587707811159987700892389251316474659535280313653455895504110202181248123584104740181548065437477883135586395419285367405510482984730579396853274696958317152079284544972182264385463
# q = 106100642585441306659231092215520826696629132542273077958343764679155770250122358609663107630938585362851298476451646865414782901804279333798979560157253536320542486164083758273933045971956834335122097138913124651325662432603430010782343379229098017062153539965098342640625730371237503614435960627380518870019
```

Once, we've factored it, we're left with a Diffie-Hellman-like encryption. 3 is raised to the `FLAG` power modulus n. To break a Diffie-Hellman encryption, it's necessary to solve the Discrete Log Problem. Unfortunately, there is no known algorithm to efficiently calculate the discrete log of extremely large numbers. However, there are two key things that allow us to actually factor this:  

- By research, I found [this post](https://crypto.stackexchange.com/questions/30328/why-does-the-modulus-of-diffie-hellman-need-to-be-a-prime) which elaborates on how to exploit a non-prime modulus in Diffie-Hellman. This means that we don't need to perform the discrete log on n, essentially square-rooting the magnitude of the modulus we're calculating it for.  

- Additionally, even though the primes are still very large, it is known that these primes are smooth numbers, i.e. the factors of $$p - 1$$ are limited to a certain upper bound. This means that $$p - 1$$ can be broken down into several smaller primes. This makes the solving the discrete log problem for these primes much faster!  

Therefore, with this knowledge, we can easily find `FLAG` using the following sage script:  

```py
p = 171737105398642886952850023587557331022400498172400869641426551638589932026649898397876829050302065185503267016434202639701993923587707811159987700892389251316474659535280313653455895504110202181248123584104740181548065437477883135586395419285367405510482984730579396853274696958317152079284544972182264385463
q = 106100642585441306659231092215520826696629132542273077958343764679155770250122358609663107630938585362851298476451646865414782901804279333798979560157253536320542486164083758273933045971956834335122097138913124651325662432603430010782343379229098017062153539965098342640625730371237503614435960627380518870019
c = '197dc99317cf5d378be7ee49eb10f018b6467abe4c671447c7dbf0aad3a0c1005bbaa4ddeb4e52c79a9dee0632e4065a5d2d7f8d2171079c8fe9940093166d6e1ef34723f1e127a3245d746c5bfeedd21fccdd365c43517efdb885b0a01069a603139f2411bb88c30729fc1a85a1c49718f103d3730f4a58900e339cde4243ec1ae98798368b956be1b98997e56f1ad1766057346ccee4cdbdb3e7f16a2387d724ac8be54673f4abba53af16f3774b16378484235eaceb126a4b2e95b7fef78add7914353828c13df6d07bd0a838e7c09e88d2944f73e1d609001998e77b90f106d451072004e554c1b0c13b6cf5e0b43620d94039c45fb055e1263d54c6b82f'
c = int(c, 16)
g = 3

R = Integers(p)
c1 = R(c)
g1 = R(g)

xp = c1.log(g1)
print(xp)

R = Integers(q)
c2 = R(c)
g2 = R(g)

xq = c2.log(g2)
print(xq)
```

Note that `xp` and `xq` actually turn out to be the same, meaning that $$x_p = x_q = x$$, where $$x=FLAG$$. If they were not, it is possible to solve for $$x$$ with Chinese Remainder Theorem.  


Once we have the flag number, we can simply convert it to bytes to get the flag:  

```py
x = 4028375274964940959020413024799108535910958820283330112174774258028392431441247073676584185406962766591101

print(long_to_bytes(x))
```

    picoCTF{b3w4r3_0f_c0mp0s1t3_m0dul1_e032a664}