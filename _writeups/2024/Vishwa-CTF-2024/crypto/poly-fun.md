---
layout: writeup
category: Vishwa-CTF-2024
chall_description:
points: 300
solves: 96
tags: crypto
date: 2024-3-3
comments: false
---

Its a simple symmetric key encryption, I am sure you will be able to solve it (what do you mean the key looks weird)

Author : Revak Pandkar

[challenge.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Vishwa-CTF-2024/challenge.py)  
[encoded_flag.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Vishwa-CTF-2024/encoded_flag.txt)  
[encoded_key.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Vishwa-CTF-2024/encoded_key.txt)  

---

Here's the source file:  

```py
import numpy as np
import random

polyc = [4,3,7]
poly = np.poly1d(polyc)


def generate_random_number():
    while True:
        num = random.randint(100, 999)
        first_digit = num // 100
        last_digit = num % 10
        if abs(first_digit - last_digit) > 1:
            return num


def generate_random_number_again():
    while True:
        num = random.randint(1000, 9999)
        if num % 1111 != 0:
            return num


def transform(num):
    number = random.randint(1, 100000)
    org = number
    number *= 2
    number += 15
    number *= 3
    number += 33
    number /= 6
    number -= org
    if number == 13:
        num1 = random.randint(1, 6)
        num2 = random.randint(1, 6)
        number = num1 * 2
        number += 5
        number *= 5
        number += num2
        number -= 25
        if int(number / 10) == num1 and number % 10 == num2:
            number = generate_random_number()
            num1 = int(''.join(sorted(str(number), reverse=True)))
            num2 = int(''.join(sorted(str(number))))
            diff = abs(num1 - num2)
            rev_diff = int(str(diff)[::-1])
            number = diff + rev_diff
            if number == 1088:
                org = num
                num *= 2
                num /= 3
                num += 5
                num *= 4
                num -= 9
                num -= org
                return num
            else:
                number = generate_random_number_again()
                i = 0
                while number != 6174:
                    digits = [int(d) for d in str(number)]
                    digits.sort()
                    smallest = int(''.join(map(str, digits)))
                    digits.reverse()
                    largest = int(''.join(map(str, digits)))
                    number = largest - smallest
                    i += 1

                if i <= 7:
                    org = num
                    num *= 2
                    num += 7
                    num += 5
                    num -= 12
                    num -= org
                    num += 4
                    num *= 2
                    num -= 8
                    num -= org
                    return num
                else:
                    org = num
                    num **= 4
                    num /= 9
                    num += 55
                    num *= 6
                    num += 5
                    num -= 23
                    num -= org
                    return num
        else:
            org = num
            num *= 10
            num += 12
            num **= 3
            num -= 6
            num += 5
            num -= org
            return num
    else:
        org = num
        num += 5
        num -= 10
        num *= 2
        num += 12
        num -= 20
        num -= org
        return num


def encrypt(p,key):
    return ''.join(chr(p(transform(i))) for i in key)


key = open('key.txt', 'rb').read()
enc = encrypt(poly,key)
print(enc)
```

Basically, this file contains a lot of checks on some operations that tell us what number is returned. To be honest, this is very easily cheesed by simply reusing the transform function on every possible character, and then creating a map that maps from output of the transform function to the corresponding character. The actual intended solution is to notice that every single check is always the same result no matter what (each sequence of operations always results in the same number), so therefore it is easy to figure out what the final result should be. (Note that each check can be easily tested with short Python scripts), and develop the same map from that.  

Once you have the map, it's easy to decode the key. Now, you're supposed to realize that the flag must first be decoded from base64 (it is clearly in the correct format) but then blindly guess (based on the fact that it's symmetric encryption) to use AES ECB. Not exactly sure why they even required you to guess that it's AES ECB, as there are many more symmetric cryptoschemes, but yeah.  

Here's my full implementation:  

```py
import numpy as np
import random
import base64
from Crypto.Cipher import AES

polyc = [4,3,7]
poly = np.poly1d(polyc) # 4x^2 + 3x + 7

# for i in range(1, 100001):
#     number = i
#     org = number
#     number *= 2
#     number += 15
#     number *= 3
#     number += 33
#     number /= 6
#     number -= org
#     if(number != 13): print(org)

# for i in range(1, 7):
#     for j in range(1, 7):
#         num1 = i
#         num2 = j
#         number = num1 * 2
#         number += 5
#         number *= 5
#         number += num2
#         number -= 25
#         if not (int(number / 10) == num1 and number % 10 == num2):
#             print(num1, num2)

def generate_random_number(): # first and last digit are more than 1 apart
    while True:
        num = random.randint(100, 999)
        first_digit = num // 100
        last_digit = num % 10
        if abs(first_digit - last_digit) > 1:
            return num

# for i in range(1000):
#     number = generate_random_number()
#     num1 = int(''.join(sorted(str(number), reverse=True)))
#     num2 = int(''.join(sorted(str(number))))
#     diff = abs(num1 - num2)
#     rev_diff = int(str(diff)[::-1])
#     number = diff + rev_diff
#     if number == 1088:
#         print(number)
        
def generate_random_number_again(): # not a multiple of 1111
    while True:
        num = random.randint(1000, 9999)
        if num % 1111 != 0:
            return num

# for a in range(100):
#     number = generate_random_number_again()
#     i = 0
#     while number != 6174:
#         digits = [int(d) for d in str(number)]
#         digits.sort()
#         smallest = int(''.join(map(str, digits)))
#         digits.reverse()
#         largest = int(''.join(map(str, digits)))
#         number = largest - smallest
#         i += 1
#     if i > 7: print(i)
        
m = dict()
for i in range(118):
    num = i
    org = num
    num *= 2
    num += 7
    num += 5
    num -= 12
    num -= org
    num += 4
    num *= 2
    num -= 8
    num -= org
    # print(chr(poly(num)), chr(i))
    m[chr(poly(num))] = chr(i)

enc_key = open("encoded_key.txt", "r").read()

key = b''
for i in enc_key:
    key += m[i].encode()
# print()
# print(m.keys())
print(key)

# literally just guess it's b64 --> AES
enc_flag = open("encoded_flag.txt", 'r').read()
enc_flag = base64.b64decode(enc_flag)

c = AES.new(key, AES.MODE_ECB)
pt = c.decrypt(enc_flag)
print(pt)
```

Run the script to get the flag!  

    VishwaCTF{s33_1_t0ld_y0u_1t_w45_345y}

### Thoughts
Crypto challenge that was secretly rev + forensics