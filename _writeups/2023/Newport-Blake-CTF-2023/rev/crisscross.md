---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/j3GuNaw.png
points: 446
solves: 45
tags: rev bits
date: 2023-12-4
comments: false
---

X  

[output.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/rev/output.txt) [main.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/rev/main.py)  

---

We're given `main.py` and `output.txt`. Here's `main.py`:  

```py
import random

key1 = random.choices(range(256), k=20)
key2 = list(range(256))
random.shuffle(key2)
flag = open('flag.txt', 'rb').read()    

def enc(n):
    q = key2[n]
    w = key1[q % 20]
    n ^= q
    return n, w

x = 0
for i, c in enumerate(flag):
    x <<= 8
    n, w = enc(c)
    if i % 2:
        n, w = w, n
    x |= n
    x |= w << ((2 * i + 1) * 8)

print(key1)
print(key2)
print(x)
```

Rather than figuring out this function by hand, I immediately copied their functions and tested it on a test flag like `nbctf{abc}`  

```py
def enc(n):
    q = key2[n]
    w = key1[q % 20]
    n ^= q
    print(q)
    return n, w

testflag = b'nbctf{abc}'
x = 0
for i, c in enumerate(testflag):
    print('\nIteration',i)
    x <<= 8
    n, w = enc(c)
    if i % 2:
        n, w = w, n
    print("{:08b}".format(n), "{:08b}".format(w))
    x |= n
    print(format(x, 'b'))
    x |= w << ((2 * i + 1) * 8)
    print(format(x, 'b'))
```

Note that, since there were a lot of bit operators, I chose to show everything in binary to get a better overview of what was happening.  

My formatted outfit very simply showed what was happening -- n and w were being written into the binary representation of x at different indices.  

Namely, n was being appended to the end of the string, while w was being inserted before all n values but after all previous w values.  

Therefore, it should be relatively simple to loop through all values and extract n and w, keeping in mind to swtich them on every odd index. Additionally, note that to find the start of all the n values, we only need to use string's `find()` function to find the binary string of the n value for the character `n`, as this is the start of the flag.  

```py
ctbin = format(ct, 'b')
midindex = ctbin.find('00001110')
ctprfx = ctbin[:midindex]
ctsuffx = ctbin[midindex:]

print(ctprfx)
print(ctsuffx)

for i in range(len(ctprfx)//8):
    w = int(ctprfx[8*(len(ctprfx)//8 - i - 1):8*(len(ctprfx)//8 - i)], 2)
    n = int(ctsuffx[8*i:8*i+8], 2)
    
    if i % 2 == 1:
        w,n = n,w
```

So now all we have to do is reverse the input to produce the flag! Should be pretty simple... right?  

In order to reverse the `enc()` function, I first sought to find q. The way I decided to do it was to loop through all possible n values (i.e. possible character values) and find their corresponding q values and the new n value (since the `enc()` function changes n).  

```py
qs = []
ns = []
for n in range(256):
    q = key2[n]
    qs.append(q)
    ns.append(n ^ q)

ntoq = dict(zip(ns, qs))
```

After this, implemenation was simple. Just convert n to q, find the original n, and convert it to a character and we should be done, right?  

```py
q = ntoq(n)
orign = key2.index(q)
print(chr(orign))
```

However, when I ran my script, I ended up getting some odd characters that didn't really fit. Why...?  

It took me a while until I finally figured out the solution. I eventually wondered -- was the mapping of n to q really a one-to-one function? What if n could produce multiple values of q?  

I immediately printed the length of my ntoq dictionary and found my mistake. `len(ntoq)` evaluated as 156, not 256 as I would expect!  

So that's what it is. In order to circumvent this, we can just consider all possible values of q for a certain n, and just use common sense to construct our flag character-by-character.  

    nbctf{cr15s_cr0ss_str4wb3rry_s4uz3}

Here is my implemenation of the solution:  
```py
key1 = [127, 81, 241, 40, 222, 128, 45, 87, 27, 154, 66, 162, 73, 176, 172, 164, 106, 234, 77, 5]
key2 = [155, 117, 124, 113, 104, 46, 151, 71, 144, 229, 152, 240, 199, 88, 103, 105, 245, 209, 13, 82, 166, 9, 201, 233, 228, 154, 19, 5, 30, 141, 81, 206, 246, 232, 107, 29, 208, 253, 187, 116, 98, 160, 60, 7, 220, 143, 80, 239, 52, 15, 94, 50, 149, 241, 57, 92, 230, 100, 31, 51, 36, 24, 39, 14, 25, 90, 101, 55, 194, 225, 157, 102, 2, 26, 148, 161, 180, 120, 223, 165, 32, 146, 185, 243, 119, 210, 172, 244, 1, 125, 44, 35, 169, 179, 188, 64, 207, 33, 137, 200, 142, 182, 250, 195, 28, 4, 79, 191, 86, 215, 96, 236, 91, 122, 196, 87, 118, 231, 126, 97, 147, 67, 132, 190, 234, 237, 43, 193, 252, 18, 212, 163, 56, 73, 123, 176, 162, 23, 192, 49, 21, 242, 171, 112, 153, 238, 203, 134, 167, 93, 115, 95, 8, 12, 65, 217, 248, 168, 219, 47, 211, 108, 76, 129, 145, 62, 156, 34, 218, 135, 48, 70, 75, 3, 249, 72, 202, 133, 183, 38, 37, 227, 164, 173, 159, 251, 0, 174, 54, 20, 136, 53, 138, 99, 226, 178, 42, 66, 150, 205, 204, 214, 197, 235, 110, 216, 63, 45, 184, 74, 41, 177, 27, 69, 130, 89, 61, 247, 255, 17, 254, 181, 131, 22, 224, 83, 189, 59, 114, 139, 111, 68, 6, 84, 11, 127, 221, 106, 77, 109, 158, 170, 16, 121, 222, 186, 10, 58, 175, 40, 128, 198, 78, 85, 213, 140]
ct = 3449711664888782790334923396354433085218951813669043815144799745483347584183883892868078716490762334737115401929391994359609927294549975954045314661787321463018287415952

qs = []
ns = []
for n in range(256):
    q = key2[n]
    qs.append(q)
    ns.append(n ^ q)

ntoq = dict()
for i in range(256):
    if ns[i] not in ntoq.keys():
        ntoq[ns[i]] = []
    ntoq[ns[i]].append(qs[i])

#ntoq = dict(zip(ns, qs))

# for n,q in ntoq.items():
#     assert key2.index(q) == n ^ q, f"{key2.index(q)}, {n^q}"

def enc(n):
    q = key2[n]
    w = key1[q % 20]
    n ^= q
    print(q)
    return n, w

testflag = b'nbctf{abc}'
x = 0
for i, c in enumerate(testflag):
    print('\nIteration',i)
    x <<= 8
    n, w = enc(c)
    if i % 2:
        n, w = w, n
    print("{:08b}".format(n), "{:08b}".format(w))
    x |= n
    print(format(x, 'b'))
    x |= w << ((2 * i + 1) * 8)
    print(format(x, 'b'))

print()
ctbin = format(ct, 'b')
midindex = ctbin.find('00001110')
ctprfx = ctbin[:midindex]
ctsuffx = ctbin[midindex:]

print(ctprfx)
print(ctsuffx)

for i in range(len(ctprfx)//8):
    w = int(ctprfx[8*(len(ctprfx)//8 - i - 1):8*(len(ctprfx)//8 - i)], 2)
    n = int(ctsuffx[8*i:8*i+8], 2)
    
    if i % 2 == 1:
        w,n = n,w
    #print(n, w, end=' | ')
    print(n,w)

    for i in ntoq[n]:
        q = i
        # assert key2.index(q) == n ^ q
        orign = key2.index(q)
        #print(q, orign, key1[q % 20], end = ' | ')
        print(chr(orign))
    print()
```