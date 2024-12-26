---
layout: writeup
category: Backdoor-CTF-2024
chall_description: 
points: 453
solves: 12
tags: misc compression huffman-coding
date: 2024-12-24
comments: false
---

Can you decompress the flag without the codes?  

nc 34.42.147.172 8009  

Author : ph03n1x  

[chall.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Backdoor-CTF-2024/chall.py)  

---

Here's `chall.py`:  

```py
#!/usr/bin/env python3

import random
from collections import Counter
from numpy import poly1d
from queue import PriorityQueue
from src.secret import flag, coeff

assert len(flag) == 49
assert len(coeff) == 6
assert all(x > 0 and isinstance(x, int) for x in coeff)

P = poly1d(coeff)


class Node:
    def __init__(self, freq, symbol, left=None, right=None):
        self.freq = freq
        self.symbol = symbol
        self.left = left
        self.right = right

    def __lt__(self, nxt):
        if self.freq == nxt.freq:
            return self.symbol < nxt.symbol

        return self.freq < nxt.freq


def get_codes(codes, node=None, val=""):
    if node:
        if not node.left and not node.right:
            codes[node.symbol] = val
        else:
            get_codes(codes, node.left, val + '0')
            get_codes(codes, node.right, val + '1')


def compress(s: str) -> str:
    cnt = Counter(s)
    codes = {}

    pq = PriorityQueue()
    for element in cnt:
        pq.put(Node(cnt[element], element))

    n_nodes = len(cnt)
    while n_nodes > 1:
        left = pq.get()
        right = pq.get()
        new = Node(left.freq + right.freq,
                   min(left.symbol, right.symbol), left, right)
        pq.put(new)
        n_nodes -= 1

    get_codes(codes, node=pq.get())

    cmprsd = ""
    for c in s:
        cmprsd += codes[c]

    # return cmprsd, codes
    return cmprsd


def get_info() -> int:
    s = list(flag)
    idx = random.randint(0, len(flag)-1)
    return P(ord(s[idx]))


def main():
    print("Welcome, agent, to the Decompressor Challenge!")
    print("Your mission, should you choose to accept it, involves unraveling the encrypted flag.")
    print("Can you decompress the flag without the codes?")
    print("Good luck, and may the odds be ever in your favor!\n")

    while True:
        print("Select your next action:")
        print("1. Retrieve compressed flag without codes.")
        print("2. Access additional intel.")
        print("3. Abort mission and exit.")

        choice = input("> ")
        if choice == "1":
            code = compress(flag)
            print(f"Compressed Flag: {code}")

        elif choice == "2":
            info = get_info()
            print(f"Additional Info: {info}")

        elif choice == "3":
            print("Mission aborted. Goodbye!")
            break

        else:
            print("Invalid choice! Please select a valid option.")

```

# Huffman Coding

Basically, this program is implementing [Huffman Coding](https://en.wikipedia.org/wiki/Huffman_coding) for the flag, but not giving us the huffman tree that we can use to decode the compressed flag. However, we are provided the option to request `Additional Info`, in which the ASCII value of a randomly chosen value is passed as input to a polynomial, which has degree 5 and whose coefficients are within the set of positive integers.  

The solution here is to recover the original Huffman Coding tree by utilizing the `Additional Info` option.  

# multithreading because why not

The first step to doing so is to get the frequencies of each character. Because the polynomial never changes, we can simply request `Additional Info` many times to get the relative frequencies. I realized that it would take a while, so I decided to implement a multithreaded version of this... it probably took more time to make it multithreaded instead of just letting it run (-‿-")  

Here is the multithreaded implementation though!  

`instance.py`  
```py
from pwn import *

with context.quiet:
    p = remote('34.42.147.172', 8009)

    p.sendlineafter(b'> ', b'1')
    cmprsd = p.recvline()[:-1].split(b' ')[-1].decode('ascii')

    d = dict()
    for i in range(1000):
        p.sendlineafter(b'> ', b'2')
        x = p.recvline()[:-1].split(b' ')[-1].decode('ascii')
        if x not in d.keys():
            d[x] = 0
        d[x] += 1

    print(d)
```

`aggregate.py`  
```py
import subprocess
import multiprocessing
from tqdm import trange


def instance(ad):
    p = subprocess.Popen(['/home/nightxade/py_venv/bin/python3', 'instance.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    d = eval(stdout)
    for k,v in d.items():
        if k not in ad.keys():
            ad[k] = 0
        ad[k] += v

manager = multiprocessing.Manager()
ad = manager.dict()

n = 100
for i in range(n):
    exec(f'p{i} = multiprocessing.Process(target=instance, args=(ad,))')
for i in trange(n):
    exec(f'p{i}.start()')
for i in trange(n):
    exec(f'p{i}.join()')

print(ad)
```

This requests `Additional Info` 100,000 times. From this, we get the frequency of each outputted number:  
```py
num_to_freq = {'22536054359758': 4072, '12089607308094': 1996, '15504583147174': 2068, '306875722638': 6052, '11485295168188': 3933, '20577758288920': 2080, '28089686233938': 8204, '31914524686710': 10386, '1327634768734': 2022, '40812896371368': 2001, '878091473854': 2066, '26899692041938': 4014, '275594854318': 4086, '19651046343154': 2013, '6292119317358': 2129, '23569580114578': 2015, '12719093260930': 4011, '1675263512638': 2079, '25750374470590': 2006, '14056716232848': 1990, '34687921557268': 6124, '16271934798450': 4019, '461629137298': 2018, '30596004264814': 2070, '340934651794': 1911, '4958875511998': 2033, '29321427339808': 4096, '1806065932258': 2051, '1129884591208': 2041, '37650860919994': 1979, '14766457937518': 2054}
```

We're told that the total length of the flag is 49, so therefore the sum of the frequencies must be 49 as well. We can pretty easily get from our current frequencies to the actual character frequencies:  

```py
num_to_freq = {int(k): (v + 100)//2000 for k,v in num_to_freq.items()}
assert sum(num_to_freq.values()) == 49
```

### unique huffman coding tree --> win! (sort of)

But how do you get from the frequencies to the original Huffman Coding tree? After all, there are several duplicate frequencies--wouldn't those characters get mixed up?  

Actually, there's a nice detail in the provided implementation of the Huffman Coding tree. If the frequencies of two characters are the same, their ASCII values are compared. So the relative ordering of the ASCII values matter too.  

What's more, we actually know the relative ordering of the ASCII values! Since the provided polynomial's coefficients are all positive, that means that, the larger the ASCII value, the larger the output of `Additional Information` for that character should be. Therefore, we know the order of the ASCII values directly correlates to the order of the numbers from `Additional Information`.  

From here, we can now assign a character to each number, ensuring that the relationship between number-ordering and ASCII-ordering is maintained by the assigned characters. We can then generate a string corresponding to the character-frequency pairs. For example, if we had `{"a": 2, "b": 3}`, we could make a string like `aabbb`. Then, we'll use the compress function of the provided `chall.py` file to make the Huffman Coding tree. Note that the order of characters in the string doesn't matter; they'll all make the exact same Huffman Coding tree.  

This new Huffman Coding tree is actually the exact same as the flag string's Huffman Coding tree! Well, almost. We don't have the right flag characters, and so we don't yet have the flag. But everything else is the same, because we maintained the order of the ASCII values.  

Therefore, we can now decompress the compressed flag string to something that's equivalent to the original flag string, except with the wrong characters assigned to each decoding.  

Here's the implementation of everything covered so far:  

```py
from pwn import *

p = remote('34.42.147.172', int(8009))

p.sendlineafter(b'> ', b'1')
cmprsd = p.recvline()[:-1].split(b' ')[-1].decode('ascii')

# from aggregate.py
num_to_freq = {'22536054359758': 4072, '12089607308094': 1996, '15504583147174': 2068, '306875722638': 6052, '11485295168188': 3933, '20577758288920': 2080, '28089686233938': 8204, '31914524686710': 10386, '1327634768734': 2022, '40812896371368': 2001, '878091473854': 2066, '26899692041938': 4014, '275594854318': 4086, '19651046343154': 2013, '6292119317358': 2129, '23569580114578': 2015, '12719093260930': 4011, '1675263512638': 2079, '25750374470590': 2006, '14056716232848': 1990, '34687921557268': 6124, '16271934798450': 4019, '461629137298': 2018, '30596004264814': 2070, '340934651794': 1911, '4958875511998': 2033, '29321427339808': 4096, '1806065932258': 2051, '1129884591208': 2041, '37650860919994': 1979, '14766457937518': 2054}
num_to_freq = {int(k): (v + 100)//2000 for k,v in num_to_freq.items()}
assert sum(num_to_freq.values()) == 49

# convert to chars, ascending order of nums == ascending order of chars because all coeffs > 0
alphabet = ''
for i in range(len(num_to_freq)):
    alphabet += chr(i + ord(b'0'))
d = list(sorted(num_to_freq.items()))
i = 0
chr_to_freq = {}
for k,v in d:
    chr_to_freq[alphabet[i]] = v
    i += 1

# compress
s = ''.join([k*v for k,v in chr_to_freq.items()])
compress(s) # impl of compress not shown here for brevity, exact same except the Huffman Coding tree was converted to a global variable to allow access when decompressing  

# decompress
rev_codes = {v: k for k,v in codes.items()}
s = ''
res = ''
for i in range(len(cmprsd)):
    s += cmprsd[i]
    if s in rev_codes.keys():
        res += rev_codes[s]
        s = ''

# assert freqs are the same still
checkd = {}
for x in res:
    if x not in checkd.keys():
        checkd[x] = 0
    checkd[x] += 1
checkd = sorted(checkd.items())
assert checkd == sorted(chr_to_freq.items())
```

For my choice of an alphabet of `0123456789:;<=>?@ABCDEFGHIJKLMN`, the decompression returns `?B;@MAHHEG411KKK0LDIHI<>0=DC1K;H=A6J573L29G:8LFKN`  

Clearly, we're not quite done yet. We still have to get the original flag characters.  

### linear algebra my love

Conveniently, however, we do know some characters! Exactly six distinct characters: the flag prefix of `flag{` and the flag suffix of `}`. So now we know that which of our currently-incorrect characters correspond to these 6 flag characters. Because of that, we also know the output of `Additional Information` that corresponds to each of these 6 flag characters. And we know that `Additional Information` relies on a polynomial of degree 5 with 6 coefficients.  

Those with some crypto/math experience will probably recognize that this just means we have a system of equations / matrix equation! We have 6 unknowns (6 coefficients) and 6 outputs. We can easily solve this using SageMath:  

```py
chr_to_num = {}
i = 0
for k,v in d:
    chr_to_num[alphabet[i]] = k
    i += 1

# create matrix equation based on 6 known values
code = res[:5] + res[-1]
print(alphabet)
print(res)
print(code)
actual = 'flag{}'
a = [[] for i in range(6)]
b = []
for i in range(6):
    b.append(chr_to_num[code[i]])
    x = ord(actual[i])
    for j in range(6):
        a[i].append(x**(5 - j))

# solve with SageMath  
a = Matrix(ZZ, a)
b = vector(ZZ, b)
coeff = a.solve_right(b)
```

Nice!  

And now that we know the polynomial behind `Additional Information`, it's trivial to iterate through all possible characters, evaluate them using the polynomial, and check if that resultant value matches any of the outputs from `Additional Information` that we have. If so, we can match that to our currently-incorrect character, and replace all of its occurences in the decompressed string with the correct flag character.  

And finally, we arrive at the flag!  

    flag{https://www.youtube.com/watch?v=B3y0RsVCyrw}

Here's the full solve script for your convenience:  

```py
from collections import Counter
from queue import PriorityQueue

class Node:
    def __init__(self, freq, symbol, left=None, right=None):
        self.freq = freq
        self.symbol = symbol
        self.left = left
        self.right = right

    def __lt__(self, nxt):
        if self.freq == nxt.freq:
            return self.symbol < nxt.symbol

        return self.freq < nxt.freq


def get_codes(codes, node=None, val=""):
    if node:
        if not node.left and not node.right:
            codes[node.symbol] = val
        else:
            get_codes(codes, node.left, val + '0')
            get_codes(codes, node.right, val + '1')


codes = {}
def compress(s: str) -> str:
    assert codes == dict()
    cnt = Counter(s)

    pq = PriorityQueue()
    for element in cnt:
        pq.put(Node(cnt[element], element))

    n_nodes = len(cnt)
    while n_nodes > 1:
        left = pq.get()
        right = pq.get()
        new = Node(left.freq + right.freq,
                   min(left.symbol, right.symbol), left, right)
        pq.put(new)
        n_nodes -= 1

    get_codes(codes, node=pq.get())

    cmprsd = ""
    for c in s:
        cmprsd += codes[c]

    # return cmprsd, codes
    return cmprsd

from pwn import *
import numpy as np
from string import printable

p = remote('34.42.147.172', int(8009))

p.sendlineafter(b'> ', b'1')
cmprsd = p.recvline()[:-1].split(b' ')[-1].decode('ascii')

# from aggregate.py
num_to_freq = {'22536054359758': 4072, '12089607308094': 1996, '15504583147174': 2068, '306875722638': 6052, '11485295168188': 3933, '20577758288920': 2080, '28089686233938': 8204, '31914524686710': 10386, '1327634768734': 2022, '40812896371368': 2001, '878091473854': 2066, '26899692041938': 4014, '275594854318': 4086, '19651046343154': 2013, '6292119317358': 2129, '23569580114578': 2015, '12719093260930': 4011, '1675263512638': 2079, '25750374470590': 2006, '14056716232848': 1990, '34687921557268': 6124, '16271934798450': 4019, '461629137298': 2018, '30596004264814': 2070, '340934651794': 1911, '4958875511998': 2033, '29321427339808': 4096, '1806065932258': 2051, '1129884591208': 2041, '37650860919994': 1979, '14766457937518': 2054}
num_to_freq = {int(k): (v + 100)//2000 for k,v in num_to_freq.items()}
assert sum(num_to_freq.values()) == 49

# convert to chars, ascending order of nums == ascending order of chars because all coeffs > 0
alphabet = ''
for i in range(len(num_to_freq)):
    alphabet += chr(i + ord(b'0'))
d = list(sorted(num_to_freq.items()))
i = 0
chr_to_freq = {}
for k,v in d:
    chr_to_freq[alphabet[i]] = v
    i += 1
chr_to_num = {}
i = 0
for k,v in d:
    chr_to_num[alphabet[i]] = k
    i += 1
num_to_chr = {}
i = 0
for k,v in d:
    num_to_chr[k] = alphabet[i]
    i += 1

# compress
s = ''.join([k*v for k,v in chr_to_freq.items()])
compress(s)

# decompress
rev_codes = {v: k for k,v in codes.items()}
s = ''
res = ''
for i in range(len(cmprsd)):
    s += cmprsd[i]
    if s in rev_codes.keys():
        res += rev_codes[s]
        s = ''

# assert freqs are the same still
checkd = {}
for x in res:
    if x not in checkd.keys():
        checkd[x] = 0
    checkd[x] += 1
checkd = sorted(checkd.items())
assert checkd == sorted(chr_to_freq.items())

# create matrix equation based on 6 known values
code = res[:5] + res[-1]
print(alphabet)
print(res)
print(code)
actual = 'flag{}'
a = [[] for i in range(6)]
b = []
for i in range(6):
    b.append(chr_to_num[code[i]])
    x = ord(actual[i])
    for j in range(6):
        a[i].append(x**(5 - j))

# solve with SageMath  
a = Matrix(ZZ, a)
b = vector(ZZ, b)
coeff = a.solve_right(b)

P = np.poly1d(coeff)

# decode from our code back to regular code
code_to_actual = {}
for c in printable:
    x = P(ord(c))
    if x in num_to_freq.keys():
        code_to_actual[num_to_chr[x]] = c

flag = ''.join([code_to_actual[c] for c in res])
print(flag)

# flag{https://www.youtube.com/watch?v=B3y0RsVCyrw}
```