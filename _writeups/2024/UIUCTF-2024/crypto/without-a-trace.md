---
layout: writeup
category: UIUCTF-2024
chall_description:
points: 246
solves: 298
tags: UIUCTF-2024 crypto
date: 2024-07-02
comments: false
---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

Gone with the wind, can you find my flag?

`ncat --ssl without-a-trace.chal.uiuc.tf 1337`

[server.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/UIUCTF-2024/trace-server.py)  

---

Here's the Python source:  

```py
import numpy as np
from Crypto.Util.number import bytes_to_long
from itertools import permutations
from SECRET import FLAG

def inputs():
    print("[WAT] Define diag(u1, u2, u3. u4, u5)")
    M = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]
    for i in range(5):
        try:
            M[i][i] = int(input(f"[WAT] u{i + 1} = "))
        except:
            return None
    return M

def handler(signum, frame):
    raise Exception("[WAT] You're trying too hard, try something simpler")

def check(M):
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

def fun(M):
    f = [bytes_to_long(bytes(FLAG[5*i:5*(i+1)], 'utf-8')) for i in range(5)]
    F = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]
    for i in range(5):
        F[i][i] = f[i]

    try:
        R = np.matmul(F, M)
        return np.trace(R)

    except:
        print("[WAT] You're trying too hard, try something simpler")
        return None

def main():
    print("[WAT] Welcome")
    M = inputs()
    if M is None:
        print("[WAT] You tried something weird...")
        return
    elif check(M) == 0:
        print("[WAT] It's not going to be that easy...")
        return

    res = fun(M)
    if res == None:
        print("[WAT] You tried something weird...")
        return
    print(f"[WAT] Have fun: {res}")

if __name__ == "__main__":
    main()

```

First blooded this challenge!  

Here's a quick outline of the key observations to make about `check()`:  

- We control only the diagonals -- every other cell of the matrix is 0  
- Because of the above property of the matrix, `check()` will only add to `res` when the permutation is in sorted/original order. (any other permutation will result in at least 2 cells filled with a 0, and since it's multiplication, `curr` will be 0)  
- `sign(sigma)` is constant since `sigma` can only be the ascending order of `[0,1,2,3,4]`.  
- Therefore, `check()` just confirms none of the user-inputted cells are 0 -- if one of them was 0, the sorted permutation also wouldn't work by the same logic explained above.  

Now explaining `fun()`:  

- The diagonals are filled with numbers calculated from the flag bytes.  
- The flag matrix is multiplied by the user-input-controlled matrix.  
- The sum of all the cells of the matrix are provided to the user.  
- Because of the shape of the flag matrix and the user-input-controlled matrix, the matrix will look like this:  

```
[
    [F[0][0] * M[0][0], 0, 0, 0, 0],
    [0, F[1][1] * M[1][1], 0, 0, 0],
    [0, 0, F[2][2] * M[2][2], 0, 0],
    [0, 0, 0, F[3][3] * M[3][3], 0],
    [0, 0, 0, 0, F[4][4] * M[4][4]],
]
```

So the server essentially gives us the dot product of two vectors, one filled with the flag numbers and one filled with our input numbers, in order.  

Since we can query the server multiple times (by just connecting multiple times), we can just send an initial `[1,1,1,1,1]` and then send `[2,1,1,1,1]`, `[1,2,1,1,1]`, etc. This will give us a nice system of equations where we can subtract, for example, the result of `[1,1,1,1,1]` from `[2,1,1,1,1]` to calculate the first flag number. Then we run `long_to_bytes()` on each flag number to calculate the entire flag!  

```py
from pwn import *
from Crypto.Util.number import long_to_bytes

arrs = [[1,1,1,1,1],[2,1,1,1,1],[1,2,1,1,1],[1,1,2,1,1],[1,1,1,2,1],[1,1,1,1,2]]
res = []

for a in arrs:
    p = remote('without-a-trace.chal.uiuc.tf', 1337, ssl=True)

    p.recvline()
    p.recvline()
    for i in a:
        p.sendlineafter(b'= ', str(i).encode())
    p.recvuntil(b': ')
    res.append(int(p.recvline().decode('ascii')[:-1]))
    p.close()

for i in range(1, len(res)):
    print(long_to_bytes(res[i] - res[0]).decode('ascii'), end='')
```

    uiuctf{tr4c1ng_&&_mult5!}