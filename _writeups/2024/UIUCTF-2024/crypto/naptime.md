---
layout: writeup
category: UIUCTF-2024
chall_description:
points: 363
solves: 180
tags: crypto knapsack merkle-hellman byte-by-byte
date: 2024-07-02
comments: false
---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

I'm pretty tired. Don't leak my flag while I'm asleep.

[pub.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/nap-pub.txt)  
[enc_dist.sage](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/nap-enc_dist.sage)  

---

Here's the source Sage file:  

```py
from random import randint
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import numpy as np

def get_b(n):
    b = []
    b.append(randint(2**(n-1), 2**n))
    for i in range(n - 1):
        lb = sum(b)
        found = False
        while not found:
            num = randint(max(2**(n + i), lb + 1), 2**(n + i + 1))
            if num > lb:
                found = True
                b.append(num)

    return b

def get_MW(b):
    lb = sum(b)
    M = randint(lb + 1, 2*lb)
    W = getPrime(int(1.5*len(b)))

    return M, W

def get_a(b, M, W):
    a_ = []
    for num in b:
        a_.append(num * W % M)
    pi = np.random.permutation(list(i for i in range(len(b)))).tolist()
    a = [a_[pi[i]] for i in range(len(b))]
    return a, pi


def enc(flag, a, n):
    bitstrings = []
    for c in flag:
        # c -> int -> 8-bit binary string
        bitstrings.append(bin(ord(c))[2:].zfill(8))
    ct = []
    for bits in bitstrings:
        curr = 0
        for i, b in enumerate(bits):
            if b == "1":
                curr += a[i]
        ct.append(curr)

    return ct

def dec(ct, a, b, pi, M, W, n):
    # construct inverse permuation to pi
    pii = np.argsort(pi).tolist()
    m = ""
    U = pow(W, -1, M)
    ct = [c * U % M for c in ct]
    for c in ct:
        # find b_pi(j)
        diff = 0
        bits = ["0" for _ in range(n)]
        for i in reversed(range(n)):
            if c - diff > sum(b[:i]):
                diff += b[i]
                bits[pii[i]] = "1"
        # convert bits to character
        m += chr(int("".join(bits), base=2))

    return m


def main():
    flag = 'uiuctf{I_DID_NOT_LEAVE_THE_FLAG_THIS_TIME}'

    # generate cryptosystem
    n = 8
    b = get_b(n)
    M, W = get_MW(b)
    a, pi = get_a(b, M, W)

    # encrypt
    ct = enc(flag, a, n)

    # public information
    print(f"{a =  }")
    print(f"{ct = }")

    # decrypt
    res = dec(ct, a, b, pi, M, W, n)

if __name__ == "__main__":
    main()

```

There's a lot of code going on here, so rather than go step-by-step through the function calls, I'll just summarize it for you.  

### super-increasing  

Basically, this cryptosystem is very similar to the Merkle-Hellman cryptosystem, more commonly known as the knapsack cryptosystem. It generates what is known as a super-increasing set of numbers. Here's an example to show you what I mean:  

`[1, 4, 7, 19, 32]`  

Basically, the next number is always greater than the sum of all previous numbers. More mathematically explained, it means:  

$$\sum_{i=0}^{n-1}a_i < a_n, \; n \in [1, len(a)]$$  

In the source code, this is the variable `b`.  

### pubkey generation

Then, two numbers `M` and `W` are generated. `W` is some sufficiently large prime that will generate the finite field over which all operations for this cryptosystem will take place.  `M` is basically some random number that is greater than the sum of the entire aforementioned super-increasing set.  

To generate the public key, each member of the super-increasing set is multiplied by `M` and then taken modulo `W`. Mathematically, it is:  

$$(\text{new } a_i) = (\text{old } a_i) * W \; (mod \; M)$$  

Now, here's where this cryptosystem slightly differs from the normal Merkle-Hellman cryptosystem.  It randomly shuffles the public key around, and keeps this permutation information private.  

### encrypting

Since the generated public key length is 8, it's perfect for encrypting byte-by-byte. The cryptosystem iterates through all bytes of the plaintext. For each byte, it iterates through its binary representation -- if it sees a 1 at index `i`, it will add the number at index `i` in the public key to `curr`. The result for each byte is appended to a ciphertext array.  

The user is then given the public key and ciphertext array.  

### lattices? LLL?? low density attack???  

You might think that we need to pull out some lattice math to solve this knapsack cryptosystem. I thought that too during the competition, and I did actually solve it that way. In fact, if you're interested, look up the `CJLOSS low density attack`. It's an interesting algorithm that I used to solve this problem.  

### but what if i don't like lattices  

That is a very based opinion. I don't blame you for not liking lattices (I don't). Thankfully, you don't need to know lattices to solve this challenge!  

Remember how this is a byte-by-byte encryption...  and how there are only 8 bits in each byte... which means there are only $$2^8=128$$ possible plaintexts for each element of the ciphertext...  

yup. just encrypt every possible plaintext byte and then map the ciphertext array back to the plaintext array.  

### i'm washed af  

I actually didn't even realize this until after the challenge 💀 I should just retire at this point  

### solve script

Anyways, here's the solve script:  

```py
import string

a =  [66128, 61158, 36912, 65196, 15611, 45292, 84119, 65338]
ct = [273896, 179019, 273896, 247527, 208558, 227481, 328334, 179019, 336714, 292819, 102108, 208558, 336714, 312723, 158973, 208700, 208700, 163266, 244215, 336714, 312723, 102108, 336714, 142107, 336714, 167446, 251565, 227481, 296857, 336714, 208558, 113681, 251565, 336714, 227481, 158973, 147400, 292819, 289507]

charset = string.ascii_letters + string.digits + string.punctuation
d = dict()
for c in charset:
    curr = 0
    bi = "{:08b}".format(ord(c))
    for i,b in enumerate(bi):
        if b == "1":
            curr += a[i]
    d[curr] = c

for c in ct:
    print(d[c], end='')
```

  uiuctf{i_g0t_sleepy_s0_I_13f7_th3_fl4g}

### TL;DR:
knapsack cryptosystem with too small of a public key so ez byte-by-byte decryption but i am blind and was probably more sleep deprived than the challenge author during the ctf