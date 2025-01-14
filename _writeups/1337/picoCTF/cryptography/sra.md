---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/3XR4FIG.png
points: 400
solves: 499
tags: picoCTF crypto crypto/rsa crypto/factorization crypto/brute-force
date: 1337-01-01
comments: false
---

I just recently learnt about the SRA public key cryptosystem... or wait, was it supposed to be RSA? Hmmm, I should probably check...  
Connect to the program on our server: `nc saturn.picoctf.net [port #]`  
Download the program: [chal.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/sra-chal.py)  

---

We’re given a file, `chal.py`, and service to connect to.  
Here's `chal.py`:  
```py
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice


pride = "".join(choice(ascii_letters + digits) for _ in range(16))
gluttony = getPrime(128)
greed = getPrime(128)
lust = gluttony * greed
sloth = 65537
envy = inverse(sloth, (gluttony - 1) * (greed - 1))


anger = pow(bytes_to_long(pride.encode()), sloth, lust)


print(f"{anger = }")
print(f"{envy = }")


print("vainglory?")
vainglory = input("> ").strip()


if vainglory == pride:
    print("Conquered!")
    with open("/challenge/flag.txt") as f:
        print(f.read())
else:
    print("Hubris!")

```

Seems like they replaced the standard RSA variable names with some of the 7 deadly sins. Let’s change it back to the standard RSA variable names.  

```py
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice


m = "".join(choice(ascii_letters + digits) for _ in range(16))
p = getPrime(128)
q = getPrime(128)
n = p * q
e = 65537
d = inverse(e, (p - 1) * (q - 1))


c = pow(bytes_to_long(m.encode()), e, n)


print(f"{c = }")
print(f"{d = }")


print("m?")
in = input("> ").strip()


if in == m:
    print("Conquered!")
    with open("/challenge/flag.txt") as f:
        print(f.read())
else:
    print("Hubris!")
```

Okay, now we can start analysis.  

This seems like standard RSA, except for the fact that we are given the private exponent d instead of n. Well, typically, in RSA, the original message $$m=c^{d}\;(mod\;n)$$ when decrypting. However, there’s a problem. We’re missing n. How can we figure out what n is?  

Immediately, I took a look at the size of p and q. They are both 128 bit primes. Rather small for RSA, but not so small that we can naively brute force it.  

Well, what does knowing d do for us? What is d anyways?  

In RSA, d is defined such that it is the modular inverse of e with respect to a modulus of $$\phi(n)$$, i.e. Euler’s totient function.  

(At least in this context, as $$\phi(n)=(p-1)(q-1)$$ in RSA, and we can clearly see that this is used as the modulus in the program, and not Carmichael's totient function, the alternative to Euler’s).  

Since d is the modular inverse of e, $$ed=1\;(mod\;\phi(n))$$.  

This can be rewritten as $$ed=1+ k\phi(n)=1+k(p-1)(q-1)$$.  

Therefore, $$ed-1=k(p-1)(q-1)$$.  

This leads to the natural thought that perhaps we can prime factorize $$ed-1$$ (there are various available functions for this like `sympy.ntheory.factorint`) and subsequently brute force $$k$$,$$(p-1)$$,$$(q-1)$$.  

Well, how can we brute force this?  

First, we can place an upper bound on the value of k. We know that p,q are 128-bit primes, i.e. $$127<log_2p<128$$ and similarly for q. Therefore, based on $$log_2(ed-1)$$, we set constraints on k.  

$$log_{2}(\frac{ed-1}{k})=log_2[(p-1)(q-1)]=log_2(p-1)+log_2(q-1)<256$$  

Since $$log_2p<128$$ and $$log_2q<128$$.  

Another way you could think about it is, if k is too large, we won’t be able to properly separate the result of $$\frac{ed-1}{k}$$ into two 128-bit numbers.  

Simultaneously, however, k cannot be too small. See the following:  

$$log_{2}(\frac{ed-1}{k})=log_2[(p-1)(q-1)]=log_2(p-1)+log_2(q-1)>254$$  

Since $$127<log_2p$$ and $$127<log_2q$$.  

Now that we have the bounds of k, we can ascertain all possible values of k.  

We can first eliminate all factors that are too large and result in $$log_2(\frac{ed-1}{factor})<256$$.  

Once we have all factors that are small enough, we can iterate through all subsets of the factors (I did so with bitwise operators) and to find the possible products of these factors. These products are the possible k values. Of these possible k values, only consider all k’s such that $$256>log_2(\frac{ed-1}{k})>254.$$  

See the following implementation:  
*Note that I slightly expanded my range for possible k’s in my code in case I had messed up with my math.*  
```py
factors = factorint(e * d - 1)


factorlist = []
for key, val in factors.items():
    for i in range(val):
        factorlist.append(key)


print(factorlist)


filteredfactors = []
for i in factorlist:
    if math.log2((e * d - 1)//i) < 256: break
    filteredfactors.append(i)


print(filteredfactors)


possk = set()
for i in range(2**len(filteredfactors)):
    currk = 1
    for j in range(len(filteredfactors)):
        if (i & (1<<j)) != 0:
            currk *= filteredfactors[j]
    if int(math.log2((e * d - 1)//currk)) <= 257 and int(math.log2((e * d - 1)//currk)) >= 254:
        possk.add(currk)


print(possk)
```

Once we have our possible values for k, all that’s left is to iterate through each possible value of k and test whether or not we have a valid pair of p,q. Here’s a short outline of the process:  

1. For each possible k
2. Make a copy of the list of all factors and remove all factors of k from that list to ensure we don’t repeat their usage.
3. Iterate through all possible subsets of these factors (again, I used bitwise operators) and find the possible products of these factors. Let each product be $$p-1$$.
4. For each $$p-1$$, check if it is a 128-bit number, i.e. $$log_2(p-1)==127$$. If it isn’t, continue onto the next possible product.
5. If it is, check if your values for p and q are prime. q can be easily computed as $$q=\frac{ed-1}{k(p-1)}+1$$. If they are not prime, continue to the next possible product.
6. If it is prime, the answer has been found!

Here is the implementation of the above:  
```py
found = 0
p = 0
q = 0
for k in possk:
    if found == 1: break
    print(k)
    kfactors = factorint(k)


    availfactors = factorlist.copy()
    for f, num in kfactors.items():
        for i in range(num):
            availfactors.remove(f)


    for i in range(2 ** len(availfactors)):
        currpminus1 = 1
        for j in range(len(availfactors)):
            if (i & (1<<j)) != 0:
                currpminus1 *= availfactors[j]
        if (int(math.log2(currpminus1)) == 127):
            currp = currpminus1 + 1
            currq = (e * d - 1)//(currpminus1 * k) + 1
            if isPrime(currp) and isPrime(currq):
                print(f'Found! p = {currp}, q = {currq}')
                p = currp
                q = currq
                found = 1
                break
```

Once you have found p and q, all that’s left is to compute n, decrypt the message with m=cd (mod n), and send in the result.  

*Only, don’t waste over an hour like I did :( and make sure to convert your final value to bytes before sending it using Python’s Crypto module’s long_to_bytes function.*

Once you send it in, open the program in interactive mode to get the flag!  

    picoCTF{7h053_51n5_4r3_n0_m0r3_b2f9b414}

Here is my full implementation:  
```py
from pwn import *
from sympy.ntheory import factorint
import math
from Cryptodome.Util.number import isPrime


target = remote('saturn.picoctf.net', 63089)
res = target.recvline().decode('ascii').split(' ')
#print(res)
c = int(res[-1][:-2])
print(c)
res = target.recvline().decode('ascii').split(' ')
#print(res)
d = int(res[-1][:-2])
print(d)


e = 65537




print(target.recvline())
print(target.recv())


factors = factorint(e * d - 1)
print(factors)
numbits = math.log2(e * d - 1)
print(numbits)


factorlist = []
for key, val in factors.items():
    for i in range(val):
        factorlist.append(key)


print(factorlist)


filteredfactors = []
for i in factorlist:
    if math.log2((e * d - 1)//i) < 256: break
    filteredfactors.append(i)


print(filteredfactors)


possk = set()
for i in range(2**len(filteredfactors)):
    currk = 1
    for j in range(len(filteredfactors)):
        if (i & (1<<j)) != 0:
            currk *= filteredfactors[j]
    if int(math.log2((e * d - 1)//currk)) <= 257 and int(math.log2((e * d - 1)//currk)) >= 254:
        possk.add(currk)


print(possk)


found = 0
p = 0
q = 0
for k in possk:
    if found == 1: break
    print(k)
    kfactors = factorint(k)
    availfactors = factorlist.copy()
    #print(kfactors)
    for f, num in kfactors.items():
        for i in range(num):
            availfactors.remove(f)
    #print(availfactors)
    for i in range(2 ** len(availfactors)):
        currpminus1 = 1
        for j in range(len(availfactors)):
            if (i & (1<<j)) != 0:
                currpminus1 *= availfactors[j]
        if (int(math.log2(currpminus1)) == 127):
            currp = currpminus1 + 1
            if (e * d - 1) % (currpminus1 * k) != 0:
                print('not divisible')
            currq = (e * d - 1)//(currpminus1 * k) + 1
            if isPrime(currp) and isPrime(currq):
                #if int(math.log2(currq) != 127):
                #    print('Found but not correct size')
                #    continue
                print(f'Found! p = {currp}, q = {currq}')
                p = currp
                q = currq
                found = 1
                break


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


if found == 1:
    print(str(pow(c, d, p * q)).encode())
    target.sendline(long_to_bytes(pow(c, d, p * q)))
    target.interactive()
else:
    print('not found :(')
```