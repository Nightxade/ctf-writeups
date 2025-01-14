---
layout: writeup
category: Vishwa-CTF-2024
chall_description:
points: 500
solves: 54
tags: Vishwa-CTF-2024 crypto crypto/rsa
date: 2024-3-3
comments: false
---

You received a package, and you got to know that you are the descendant of RIADSH. There are four files and a safe in the package.

You should analyze the files, unlock the safe, and prove your worth. The safe has alphanumeric and character combinations.

PS: The safe has no lowercase buttons.

Author : Abhishek Mallav

[package.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Vishwa-CTF-2024/package.zip)  

---

We're provided 3 files and a source file in package.zip. Here's the source:  

```py
# my secret to hide the combination of my safe in fornt of all without anyone getting a clue what it is ;)

#some boring python function for conversion nothing new
def str_to_ass(input_string):
    ass_values = []
    for char in input_string:
        ass_values.append(str(ord(char)))
    ass_str = ''.join(ass_values)
    return ass_str

input_string = input("Enter the Combination: ")
result = str_to_ass(input_string)
msg = int(result)

#not that easy, you figure out yourself what the freck is a & z
a = 
z = 

f = (? * ?) #cant remember what goes in the question mark
e = #what is usually used

#ohh yaa!! now you cant figure out $h!t
encrypted = pow(msg, e, f)
print(str(encrypted))

#bamm!! protection for primes
number = 
bin = bin(number)[2:]

#bamm!! bamm!! double protection for primes
bin_arr = np.array(list(bin), dtype=int)
result = np.sin(bin_arr)
result = np.cos(bin_arr)
np.savetxt("file1", result)
np.savetxt("file2", result)

```

As you might notice, this source file is very confusing. My teammate helped out by pointing out that a and z are probably p and q, and f is probably n. Eventually, by taking a look at file1.txt and file2.txt (and realizing they make no logical sense given the code), I guessed that `number` probably represented p and q (again, how does this work in the source code? this is 100% more of a rev + forensics problem than a crypto problem). And thus, the values in file1.txt and file2.txt were probably binary. I just assumed that the first value listed in each of file1.txt and file2.txt was 1, and the other value was 0, and it worked out to give me p and q. After that, it's standard RSA decryption and then **not** long_to_bytes as usual but instead basically unhexlifying str(pt). Here's the final implementation:  

```py
from Crypto.Util.number import *

f1 = open('file1.txt', 'r').read().replace('\n', '')
f2 = open('file2.txt', 'r').read().replace('\n', '')

f1 = f1.replace('5.403023058681397650e-01', '1')
f1 = f1.replace('1.000000000000000000e+00', '0')
f2 = f2.replace('8.414709848078965049e-01', '1')
f2 = f2.replace('0.000000000000000000e+00', '0')

f1 = "".join(f1)
f2 = "".join(f2)

p = int(f1, 2)
q = int(f2, 2)

assert isPrime(p)
assert isPrime(q)

n = p*q
phi = (p - 1)*(q - 1)
e = 65537
d = inverse(e, phi)

ct = int(open('file.txt', 'r').read())
pt = str(pow(ct, d, n))
print(pt)
for i in range(0, len(pt), 2):
    print(chr(int(pt[i:i+2])), end='')
```

And here's the flag:  

    VishwaCTF{Y0U_@R3_T#3_W0RT#Y_OF_3}