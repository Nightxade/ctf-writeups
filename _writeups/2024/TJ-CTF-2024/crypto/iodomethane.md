---
layout: writeup
category: TJ-CTF-2024
chall_description:
points: 205
solves: 29
tags: crypto crypto/matrix
date: 2024-5-19
comments: false
---

AINT NO HILL HIGH ENOUGH....

[out.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/iodomethane/out.txt)  
[main.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/TJ-CTF-2024/iodomethane/main.py)  

---

Here's the Python source:  

```py
import secrets

flag = open("flag.txt", "r").read().strip()

print(flag)

matrix = [[],[],[]]

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0192834756{}_!@#$%^&*()"

modulus = 15106021798142166691 #len(alphabet)

flag = [alphabet.index(a) for a in flag]


while len(flag) % 3 != 0:
    flag.append(secrets.randbelow(modulus))


def det(matrix):
    a = matrix[0][0]
    b = matrix[0][1]
    c = matrix[0][2]
    d = matrix[1][0]
    e = matrix[1][1]
    f = matrix[1][2]
    g = matrix[2][0]
    h = matrix[2][1]
    i = matrix[2][2]
    return ((a * e * i - a * f * h) + (b * f * g - b * d * i) + (c * d * h - c * e * g)) % modulus

def randkey():
    test = [[secrets.randbelow(modulus) for i in range(3)] for J in range(3)]
    while (not det(test)):
           test = [[secrets.randbelow(modulus) for i in range(3)] for J in range(3)]
    return test

def dot(a,b):
    return sum([a[i] * b[i] for i in range(len(a))]) % modulus

def mult(key, row):
    return [dot(key[i], row) for i in range(len(key))]

rows = list(zip(flag[::3], flag[1::3], flag[2::3]))

key = randkey()
print(key, det(key), modulus)

enc = sum([mult(key, snip) for snip in rows], start = [])
print(enc)
open("out.txt", "w+").write(str(enc))

```

Let's walk through exactly what's happening.  


## Step 1

```py
flag = [alphabet.index(a) for a in flag]


while len(flag) % 3 != 0:
    flag.append(secrets.randbelow(modulus))
```

Here, the flag is converted such that each byte becomes the byte's index in the string "alphabet", which is of length 75. Then, the flag is padded so that its length is a multiple of 3. For example, if the flag is "tjctf{f4k3_fl46}", it might look something like this:  

```py
[19, 9, 2, 19, 5, 62, 5, 58, 10, 57, 64, 5, 11, 58, 61, 63, 8663296688968513193, 1557885647606936801]
```


## Step 2

```py
rows = list(zip(flag[::3], flag[1::3], flag[2::3]))
```

This operation (by just using a sample flag and running it) just splits the flag into groups of 3 bytes. Let's use the same example from before:  

```py
[(19, 9, 2), (19, 5, 62), (5, 58, 10), (57, 64, 5), (11, 58, 61), (63, 8663296688968513193, 1557885647606936801)]
```


## Step 3

```py
def det(matrix):
    a = matrix[0][0]
    b = matrix[0][1]
    c = matrix[0][2]
    d = matrix[1][0]
    e = matrix[1][1]
    f = matrix[1][2]
    g = matrix[2][0]
    h = matrix[2][1]
    i = matrix[2][2]
    return ((a * e * i - a * f * h) + (b * f * g - b * d * i) + (c * d * h - c * e * g)) % modulus

def randkey():
    test = [[secrets.randbelow(modulus) for i in range(3)] for J in range(3)]
    while (not det(test)): # det(key) != 0
           test = [[secrets.randbelow(modulus) for i in range(3)] for J in range(3)]
    return test

key = randkey()
```

This is the key generation function. All it does is generate 9 random nonnegative integers below the modulus for a 3x3 matrix. The resultant matrix's determinant is ensured to not be 0.  

Let's say our key is this:  

```py
[
    [11129846811433172972, 264795847042417231, 12786127660047114284],
    [6984029699524514299, 8385153418510495656, 9952071162317785417],
    [12173872960170950772, 13281922566309990632, 13513773043911719023]
]
```

## Step 4

```py
def dot(a,b):
    return sum([a[i] * b[i] for i in range(len(a))]) % modulus

def mult(key, row):
    return [dot(key[i], row) for i in range(len(key))]

enc = sum([mult(key, snip) for snip in rows], start = [])
```

Finally, we come to the encryption step. Note that the `sum()` function does not actually serve any purpose other than to flatten the ciphertext array down to a 1-dimensional array.  

During the actual encryption, we iterate through all the rows of the flag bytes. For each row, we iterate through all 3 rows of the key matrix, computing the dot product for each one. We then return the dot product results for each row and key combination.  

Let's do it for the first row to see what's happening:  

```py
row = rows[0] = (19, 9, 2)
key = [
    [11129846811433172972, 264795847042417231, 12786127660047114284],
    [6984029699524514299, 8385153418510495656, 9952071162317785417],
    [12173872960170950772, 13281922566309990632, 13513773043911719023]
]

dot(key[0], row) = (11129846811433172972*19 + 264795847042417231*9 + 12786127660047114284*2) % modulus
dot(key[1], row) = (6984029699524514299*19 + 8385153418510495656*9 + 9952071162317785417*2) % modulus
dot(key[2], row) = (12173872960170950772*19 + 13281922566309990632*9 + 13513773043911719023*2) % modulus

result = [12832180388573769750, 1476760410063303054, 217890474307251127]
```

This repeats itself for all the rows to return this:  

```py
[
    [12832180388573769750, 1476760410063303054, 217890474307251127],
    [8533544897980456625, 6137609943828277883, 2615492936662095429],
    [2490386410249040115, 1432864670580339382, 14679230802994899213],
    [5295816249959299131, 2608450589917129197, 10284357590072520321],
    [11378953428569071954, 7075887412816480567, 6517782098267772777],
    [4220528819464674859, 6276519725400122300, 554722810896478431]
]
```

This gets flattened to become this array:  

```py
[12832180388573769750, 1476760410063303054, 217890474307251127, 8533544897980456625, 6137609943828277883, 2615492936662095429, 2490386410249040115, 1432864670580339382, 14679230802994899213, 5295816249959299131, 2608450589917129197, 10284357590072520321, 11378953428569071954, 7075887412816480567, 6517782098267772777, 4220528819464674859, 6276519725400122300, 554722810896478431]
```

Which is similar in form to what we were provided in out.txt.  

So, we're essentially just using a randomized key matrix, performing matrix multiplication between the flag byte matrix and key matrix, and returning the result. So... how can we break this?  


## System of equations...?

Well, take a look at the encryption operation:  

```py
dot(key[0], row) = (11129846811433172972*19 + 264795847042417231*9 + 12786127660047114284*2) % modulus
dot(key[1], row) = (6984029699524514299*19 + 8385153418510495656*9 + 9952071162317785417*2) % modulus
dot(key[2], row) = (12173872960170950772*19 + 13281922566309990632*9 + 13513773043911719023*2) % modulus
```

That's... kind of like a system of equations, right? Except, there's a slight problem here. In this, it seems like the variables are 19, 9, and 2, the bytes of the flag, and the key matrix values are the coefficients. If we can get the coefficients, we can pretty easily solve this system of equations, as we have 3 variables and 3 equations! But that means we need a total break of this system by recovering the key. How can we do that?  


## System of equations!!!

Well, systems of equations actually helps here once again. Consider the encryption of the first 3 rows of the flag bytes with *only* the first key matrix row. And, just so we don't confuse ourselves, let's stop using our example numbers and replace them with variables.  

```py
dot(key[0], rows[0]) = (key[0][0]*19 + key[0][1]*9 + key[0][2]*2) % modulus
dot(key[0], rows[1]) = (key[0][0]*19 + key[0][1]*5 + key[0][2]*62) % modulus
dot(key[0], rows[2]) = (key[0][0]*flag[2][0] + key[0][1]*flag[2][1] + key[0][2]*flag[2][2]) % modulus
```

Note that we know the flag bytes of the first two rows because we know the flag starts with the prefix "tjctf{".  

Now, notice that the key matrix and the flag bytes have switched positions! Now, the key bytes seem like the variables of the equation, while the flag bytes seem like the coefficients.  

However, we have a slight problem. It is easy to solve a 3-variable 3-equation system of equations under a modulus/in an integer field by using some matrix functions provided by SageMath, but we're missing 3 coefficients. How do we deal with that?  

Well, conveniently, `alphabet` is only 75 characters long. 75^3 is 421875, which is pretty small! Therefore, we can just brute force those 3 missing flag bytes!  

Once we find the correct 3 flag bytes, we can easily use SageMath to solve the system of equations and recover the key matrix. From there, we can then turn back to the other system of equations, where the group of 3 flag bytes are the variables and the key matrix is the coefficients, and use the same exact SageMath function to solve the system of equations and get the flag bytes!  

Perfect. Now we can just implement in Sage and solve!  

It took me a while to debug, but here's the implementation:  

```py
from tqdm import trange

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0192834756{}_!@#$%^&*()"
LEN = len(alphabet)
R = IntegerModRing(15106021798142166691)
res = [8103443654527565038, 9131436358818679900, 4957881569325453096, 10608823513649500284, 6675039786579943629, 6611905972844131155, 1244757961681113340, 7547487070745190563, 1913848887301325654, 9737862765813246630, 2820240734893834667, 4787888165190302097, 11681061051439179359, 11976272630379115896, 2884226871403054033, 13149362434991348085, 2676520484503789480, 6933002550284269375, 6634913706901406922, 3790038065981008837, 7593117393518680210, 1266282031812681717, 14297832010203960867, 6803759075981258244, 2235840587449302546, 9573113061825958419, 7208484535445728720, 3230648965441849617, 14844603229849620928, 2548590493342454145, 12648684202717570605, 8664656898390315577, 13502288186462622020, 8391628990279857365, 5501744205282111713, 5327399420219427046, 904912426181632886, 4805354280735678357, 12915117098149429818, 12340346813869037506, 9907136040657333887, 12822605127735793613]
ys = [res[0:9:3], res[1:9:3], res[2:9:3]]
Y = Matrix(R, ys)

m = [[19, 9, 2], [19, 5, 62]]
for i in range(LEN):
    for j in range(LEN):
        for k in range(LEN):
            K = False
            y = False
            try: 
                M = m.copy()
                M.append([i, j, k])
                M = Matrix(R, M)

                key_guess = [list(M.solve_right(Y[l])) for l in range(3)]
                K = Matrix(R, key_guess)

                flag_guess = alphabet[i] + alphabet[j] + alphabet[k]

                # y = vector(R, res[0:3])
                # print(K.solve_right(y))


                for l in range((len(res) - 9)//3):
                    if l > 0:
                        print(i, j, k, l)
                        print(flag_guess)

                    y = vector(R, res[l*3+9:l*3+12])

                    flag_part = list(K.solve_right(y))
                    for num in flag_part:
                        flag_guess += alphabet[num]

                print('Passed!', flag_guess)
            except:
                pass
    #     break
    # break
    a = input()
    if a == 'q':
        exit()
```


## wtf where'd the last bytes go D:

Yeah so... turns out the program isn't perfect. It doesn't decrypt the last group of 3 bytes. I realized that it's probably because of the padding, i.e. the last byte or two is some random large number less than the modulus, and for some reason it's screwing up the program.  

So far, though, I had most of the flag:  

`tjctf{aint_no_hillllll_55e4$S56a356^#@`.  

So how can we correct the program and get the full flag?  


## n a h

We know the end of the flag is '}', and the last part of the 3 byte group is probably padding. That means there's only one byte of the flag left that we don't know!  

Looking at the end of the flag we have so far, it seems likely that it's going to be a special symbol. Sooooo I just started guessing.  

    tjctf{aint_no_hillllll_55e4$S56a356^#@!$}

:))