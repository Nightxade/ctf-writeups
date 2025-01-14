---
layout: writeup
category: UIUCTF-2024
chall_description:
points: 322
solves: 222
tags: UIUCTF-2024 crypto crypto/rsa crypto/gcd
date: 2024-07-02
comments: false
---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

"It is my experience that proofs involving matrices can be shortened by 50% if one throws the matrices out."

Emil Artin

`ncat --ssl determined.chal.uiuc.tf 1337`

[server.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/det-server.py)  
[gen.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/det-gen.py)  
[gen.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/det-gen.txt)  

---

Here's gen.py:  

```py
from SECRET import FLAG, p, q, r
from Crypto.Util.number import bytes_to_long
n = p * q
e = 65535
m = bytes_to_long(FLAG)
c = pow(m, e, n)
# printed to gen.txt
print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
```

Here's server.py:  

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes
from itertools import permutations
from SECRET import FLAG, p, q, r



def inputs():
    print("[DET] First things first, gimme some numbers:")
    M = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]
    try:
        M[0][0] = p
        M[0][2] = int(input("[DET] M[0][2] = "))
        M[0][4] = int(input("[DET] M[0][4] = "))

        M[1][1] = int(input("[DET] M[1][1] = "))
        M[1][3] = int(input("[DET] M[1][3] = "))

        M[2][0] = int(input("[DET] M[2][0] = "))
        M[2][2] = int(input("[DET] M[2][2] = "))
        M[2][4] = int(input("[DET] M[2][4] = "))

        M[3][1] = q
        M[3][3] = r

        M[4][0] = int(input("[DET] M[4][0] = "))
        M[4][2] = int(input("[DET] M[4][2] = "))
    except:
        return None
    return M

def handler(signum, frame):
    raise Exception("[DET] You're trying too hard, try something simpler")

def fun(M):
    def sign(sigma):
        l = 0
        for i in range(5):
            for j in range(i + 1, 5):
                if sigma[i] > sigma[j]:
                    l += 1
        return (-1)**l

    res = 0
    for sigma in permutations([0,1,2,3,4]):
        curr = 1
        for i in range(5):
            curr *= M[sigma[i]][i]
        res += sign(sigma) * curr
    return res

def main():
    print("[DET] Welcome")
    M = inputs()
    if M is None:
        print("[DET] You tried something weird...")
        return

    res = fun(M)
    print(f"[DET] Have fun: {res}")

if __name__ == "__main__":
    main()

```

gen.txt doesn't provide any particularly revealing information -- the main challenge lies in breaking server.py, not the RSA part, as gen.py is literally just standard RSA encryption.  

## server.py analysis

We are allowed to fill in particular parts of the matrix `M`. I'll denote user-controlled inputs with an `X`.  

```python
[
    [p, 0, X, 0, X],
    [0, X, 0, X, 0],
    [X, 0, X, 0, X],
    [0, q, 0, r, 0],
    [X, 0, X, 0, 0],
]
```

### p, q, and... r?

Importantly, `p`, `q`, and `r` are part of the matrix. But `r` isn't part of the RSA encryption process at all...? Hmmm. That's odd. Definitely something to note.  

It then calls `fun(M)`. Notice that `fun()` is actually very similar to the `check()` function from the crypto challenge Without a Trace.  

Let's ignore `sign()` for now, and focus on the part after that:  

```py
res = 0
for sigma in permutations([0,1,2,3,4]):
    curr = 1
    for i in range(5):
        curr *= M[sigma[i]][i]
    res += sign(sigma) * curr
return res
```

Basically, this iterates through all the possible choices of cells of the matrix such that there is only one selected cell in each row and column (think Sudoku) and multiplies those cells, as well as the result of `sign(sigma)`, and adds that to `res`. We are then given `res`.  

Importantly, for a specific permutation of `[0,1,2,3,4]`, if any of the selected cells are 0, it will add nothing to `res`. This is very interesting, because if we can essentially isolate a single permutation, making sure all the other ones add nothing to `res`, `res` will be the product of `sign(the isolated permutation) * (product of selected cells)`.  

### sign()...?  

`sign()` doesn't actually matter. If you take a look at the return value, it will always return `1` or `-1`. Since we're going to be trying to isolate a single permutation, it won't matter -- we can just take the absolute value of the result to get the product of the selected cells.  

### how to matrix

Well, how do we set up our matrix such that we isolate a single permutation and crack the RSA encryption?  

Turns out, this one works:  

```py
[
    [p, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, q, 0, r, 0],
    [0, 0, 1, 0, 0],
]
```

Let me first explain how this isolates a single permutation.  

Remember that `fun()` essentially iterates through all combinations of five cells such that each row and column contain one cell each. In this matrix, only one combination works such that no cell contains 0. Confirm for yourself that it is the following combination cells:  

`(0,0), (1,1), (2,4), (3,3), (4,2)`.  

And the corresponding numbers are:  

`p      1      1      r      1`.  

So the absolute value of the number the server spits back to us should be $$p \cdot 1 \cdot 1 \cdot r \cdot 1=pr$$  

### but why pr???  

Well, remember that `r` was included in this matrix but not the RSA encryption process? Yeah... that's really weird.  

Well, in order to crack the RSA encryption, we basically want to factor the modulus `n`, which is the product of `p` and `q`. Well, what if we found something like, say, `pr`. Then, we can take the GCD of `pr` and `pq`, which is known to be much faster than prime factorizing a number, and get `p`.  

And that's that! Send in the correct input numbers to fill in the matrix like listed above, get `pr`, take the GCD of `pr` and `pq`, and get the flag!  

```py
from Crypto.Util.number import *

n = 158794636700752922781275926476194117856757725604680390949164778150869764326023702391967976086363365534718230514141547968577753309521188288428236024251993839560087229636799779157903650823700424848036276986652311165197569877428810358366358203174595667453056843209344115949077094799081260298678936223331932826351
e = 65535
c = 72186625991702159773441286864850566837138114624570350089877959520356759693054091827950124758916323653021925443200239303328819702117245200182521971965172749321771266746783797202515535351816124885833031875091162736190721470393029924557370228547165074694258453101355875242872797209141366404264775972151904835111

pr = 89650932835934569650904059412290773134844226367466628096799329748763412779644167490959554682308225788447301887591344484909099249454270292467079075688237075940004535625835151778597652605934044472146068875065970359555553547536636518184486497958414801304532202276337011187961205104209096129018950458239166991017

p = GCD(pr, n)
q = n//p
assert p*q == n
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)))

'''
[DET] M[0][2] = 0
[DET] M[0][4] = 0
[DET] M[1][1] = 1
[DET] M[1][3] = 0
[DET] M[2][0] = 0
[DET] M[2][2] = 0
[DET] M[2][4] = 1
[DET] M[4][0] = 0
[DET] M[4][2] = 1
'''
```

    uiuctf{h4rd_w0rk_&&_d3t3rm1n4t10n}