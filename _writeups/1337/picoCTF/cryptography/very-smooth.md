---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/tpXXcLh.png
points: 300
solves: 1135
tags: crypto crypto/rsa crypto/smooth-primes crypto/pollard-attack
date: 1337-01-01
comments: false
---

Forget safe primes... Here, we like to live life dangerously... >:)  

- [gen.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/very-smooth-gen.py)
- [output.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/very-smooth-output.txt)

---

We’re given two files, `gen.py`, which was used to encrypt the flag, and `output.txt.` Here is `gen.py` with my analysis comments:  
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

_DEBUG = True

FLAG  = open('flag.txt').read().strip()
FLAG  = mpz(hexlify(FLAG.encode()), 16)
SEED  = mpz(hexlify(os.urandom(32)).decode(), 16)
STATE = random_state(SEED)

def get_prime(state, bits):
    return next_prime(mpz_urandomb(state, bits) | (1 << (bits - 1))) 

# random(0, 2**(bits - 1)), inclusive | 2**(bits - 1) --> random() + 2**(bits - 1)
# adds 2**(bits - 1) unless random = 2**(bits - 1)
# next prime number greater than above
# always less than 2**(bits)

def get_smooth_prime(state, bits, smoothness=16):
    p = mpz(2)
    p_factors = [p]
    while p.bit_length() < bits - 2 * smoothness: # 992 for p, 990 for q
        factor = get_prime(state, smoothness)  

# gets smaller primes for p, larger primes for q
# always 2**(smoothness - 1) <= prime < 2**(bits)
        
        p_factors.append(factor)
        p *= factor

    bitcnt = (bits - p.bit_length()) // 2 # half of the remaining bits left to get to 1024 bits

    while True:
        prime1 = get_prime(state, bitcnt) # halfway to 1024 bits
        prime2 = get_prime(state, bitcnt) # also halfway to 1024 bits
        # together they should get to 1024 bits (or at least close)
        tmpp = p * prime1 * prime2
        if tmpp.bit_length() < bits:
            bitcnt += 1
            continue
        if tmpp.bit_length() > bits:
            bitcnt -= 1
            continue
        # above two if statements make sure that p will be 1024 bits
        if is_prime(tmpp + 1):
            p_factors.append(prime1)
            p_factors.append(prime2)
            p = tmpp + 1
            break

    p_factors.sort()

    return (p, p_factors) # p = all p_factors multiplied and then +1

e = 0x10001

while True:
    p, p_factors = get_smooth_prime(STATE, 1024, 16) # smoothness = 16
    if len(p_factors) != len(set(p_factors)): # if not all distinct primes
        continue
    # Smoothness should be different or some might encounter issues
    q, q_factors = get_smooth_prime(STATE, 1024, 17) # smoothness = 17
    if len(q_factors) != len(set(q_factors)):
        continue
    factors = p_factors + q_factors
    if e not in factors: # e can't be in factors
        break

# above while loop results in distinct primes in p_factors, q_factors;
# e is not in p_factors or e_factors

if _DEBUG:
    import sys
    sys.stderr.write(f'p = {p.digits(16)}\n\n')
    sys.stderr.write(f'p_factors = [\n')
    for factor in p_factors:
        sys.stderr.write(f'    {factor.digits(16)},\n')
    sys.stderr.write(f']{len(p_factors)}\n\n')

    sys.stderr.write(f'q = {q.digits(16)}\n\n')
    sys.stderr.write(f'q_factors = [\n')
    for factor in q_factors:
        sys.stderr.write(f'    {factor.digits(16)},\n')
    sys.stderr.write(f']{len(q_factors)}\n\n')

n = p * q

m = math.lcm(p - 1, q - 1)
d = pow(e, -1, m)

c = pow(FLAG, e, n)

print(f'n = {n.digits(16)}')
print(f'c = {c.digits(16)}')
```

After analyzing `gen.py`, I decided to do some research about what “smooth” numbers were, as that seemed to be what the problem was implying. I found [this Wikipedia page](https://en.wikipedia.org/wiki/Smooth_number#:~:text=In%20number%20theory%2C%20an%20n,13%20are%20not%207%2Dsmooth.) about it.  

Reading through it, I realized that *B-smooth numbers* are numbers with **no** prime factors greater than B. Given my program analysis, I realized that $$p-1$$ is a $$2^{16}$$-smooth number, and $$q-1$$ is a $$2^{17}$$-smooth number. So our problem likely somehow deals with smooth numbers in RSA.  

I did a little bit of Googling until I found [this article](https://www.mdpi.com/2073-8994/14/2/312). The title included something called Pollard’s attack, so I searched that up. This time, I found a [Columbia University article](https://www.math.columbia.edu/~goldfeld/PollardAttack.pdf) about Pollard’s attack, which explained how it could be used to break RSA when $$p-1$$ is a B-smooth number. Now we’re getting somewhere!  

At this point, I understood the process. All I needed to do was confirm that this would run in time, given that it seemed like we needed to compute $$65537!$$, which would certainly be very large. Thankfully, [this program](https://github.com/sandeshc/pollard-rho-attack/blob/master/pollardRhoAttack.py) clarified for me that I did not have to in fact compute $$65537!$$ and that the program would run in time with a worst case time complexity of $$O( ( B * log(B) + log(N) ) * log^2(N) )$$.  

Therefore, here is the implementation of the solution:  

```py
from gmpy2 import *
import binascii

n = 'a1355e27e1419c3f129f1db20915bf2a2d8db159b67b55858ccb2fbe4c6f4f8245411928326496b416f389dc88f6f89f1e7dc2f184a4fb5efd40d53c4f578bd4643aea45971c21bde2ddfc6582c2955466cb8f5f2341d11ad3bdcb678efeadd043d203105545d104b1c6bde632fe72e89e37af6c69b8ca3c0d7f1367e3f9967f719e816ff603544530999eda08d28b6390fc9e3c8e0eb7432e9506bf5e638c4f548dd8c6c6c0791915f2e31b4f4114c89036650ebf541fec907017d17062114f6d2008aa641166a27734c936e7cb0f4c9df4ca5c7b57019901cbb4f3d3bbc78befbfb770ca8cbf0f3d9b752d55b81f57379e9a13bd33cf3ee17f131c16db8b21'
c = '73d31ba14f88d1343a774e5d4315e1733af382318d7bf99116e5e42f0b11dc9561dfa7eafca3e061504538396fd5e463247596e8524df1c51600644d9ea7e607d5be8f79ef237907616d2ab958debc6bef12bd1c959ed3e4c2b0d7aff8ea74711d49fc6e8d438de536d6dd6eb396587e015289717e2c6ea9951822f46aae4a8aa4fc2902ceeddefd45e67fe6d15a6b182bafe8a254323200c728720bfd2d727cc779172f0848616ed37d467179a6912e8bbeb12524c7ac5cda79eee31b96cc7e36d9d69ef673f3016d0e6f0444b4f9de3d05f9d483ee6c1af479a0ffb96e9efab8098e12c7160fe3e4288364be80633a637353979c3d62376abfc99c635b703c'

n = int(n, 16)
c = int(c, 16)

'''
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
'''
p = 154714566007807784658217453973430067124002427483243197849791456415176834246233278559337287163780143729239757891659989122025191209127201898935320797851763250468612618658207399696173578206890458794774190054174795187906918498063579076533339922893829854809748220803577061068137039229503960574560413271008097993583
q = n // p
phi = lcm(p - 1, q - 1)
e = 0x10001
d = pow(e, -1, phi)
m = pow(c, d, n)
m = format(m, 'x')
print(binascii.unhexlify(m))
```


    picoCTF{p0ll4rd_f4ct0r1z4at10n_FTW_148cbc0f}
