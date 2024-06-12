---
layout: writeup
category: BCA-CTF-2024
chall_description:
points: 150
solves: 100
tags: crypto error-checking
date: 2024-06-12
comments: false
---

My friend seems to be communicating something but I can't make out anything. Why do we live so close to Chernobyl anyways?

[message.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/rad_message.py)  
[output.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/rad_output.txt)  

---

Here's the Python source:  

```py
import random
def find_leftmost_set_bit(plaintext):
    pos = 0
    while plaintext > 0:
        plaintext = plaintext >> 1
        pos += 1
    return pos
        
def encrypt(plaintext: str):
    enc_plaintext = ""

    for letter in plaintext:
        cp = int("10011", 2)
        cp_length = cp.bit_length()
        bin_letter, rem = ord(letter), ord(letter) * 2**(cp_length - 1)
        while (rem.bit_length() >= cp_length):
            first_pos = find_leftmost_set_bit(rem)
            rem = rem ^ (cp << (first_pos - cp_length))
        enc_plaintext += format(bin_letter, "08b") + format(rem, "0" + f"{cp_length - 1}" + "b")
        
    return enc_plaintext

def rad(text: str):
    corrupted_str = ""
    for ind in range(0, len(text), 12):
        bit_mask = 2 ** (random.randint(0, 11))
        snippet = int(text[ind : ind + 12], base = 2)
        rad_str = snippet ^ bit_mask
        corrupted_str += format(rad_str, "012b")
    return corrupted_str

def main():
    with open('flag.txt') as f:
        plaintext = f.read().strip()
    enc_plaintext = encrypt(plaintext)
    cor_text = rad(enc_plaintext)
    print(cor_text)

if __name__ == '__main__':
    main()
```

Basically, for every 12-bit string, the first 8 bits is equivalent to the ASCII code. The remaining 4 bits are deterministically calculated from the ASCII code of the original character. **But**, one random bit of the 12 is flipped.  

To solve this, we can calculate the 4-bit codes of every possible character. Some of them will repeat since there are only 16 possible 4-bit codes and there are 128 ASCII characters. Therefore, for every 4-bit code, we will make an array of the possible ASCII characters.  

Then, for every 12-bit string, we'll take the first 8 bits and create a set of all the possible corresponding ASCII characters, flipping one of the bits each time. We'll also take the last 4 bits and match it to the corresponding possible ASCII character set. We will then find the intersection of these two sets.  

If a bit was flipped in the first 8 bits, the intersection of the 2 sets should produce the correct ASCII character. If a bit was flipped in the last 4 bits instead, the intersection of the 2 sets will be empty, in which case the 8 bits correspond to the correct ASCII character.  


Thus, here is the solve script:  

```py
from Crypto.Util.number import *
import string

def find_leftmost_set_bit(plaintext):
    pos = 0
    while plaintext > 0:
        plaintext = plaintext >> 1
        pos += 1
    return pos

def encrypt(plaintext: str):
    enc_plaintext = ""

    for letter in plaintext:
        cp = int("10011", 2)
        cp_length = cp.bit_length()
        bin_letter, rem = ord(letter), ord(letter) * 2**(cp_length - 1)
        while (rem.bit_length() >= cp_length):
            first_pos = find_leftmost_set_bit(rem)
            rem = rem ^ (cp << (first_pos - cp_length))
        enc_plaintext += format(bin_letter, "08b") + format(rem, "0" + f"{cp_length - 1}" + "b")
        
    return enc_plaintext

ct = '011000001011010000111000011000111110011000111100011101001100001001100111011111110110011110010100011100010111011011111001010011011011010100011010001010011110010110010000001110111010001000011100011100011100010011111101010101101011110000110010001101100011011010100011001001010010001011011111011110000010001101100110010000110011011101110101010010111000011100011001010100011001001000111000001101010001011000100111010011000001011100011111111101010111010001001000001101000000001101011100010101101010101011011110011010100010010010010011010101010101010000010000001011011100011000011010010000111110001110011111011100011101010110001010010100100111001110011100011010101000011000101010001000101001001100011101111101100010010011100000010101111010011101101000011100100101001001000001010001111111010001001101111110100101011111001100'

a = []
b = []
for i in range(len(ct)//12):
    a.append(ct[i*12:i*12+8])
    b.append(ct[i*12+8:i*12+12])

charset = ''
for i in range(32, 128):
    charset += chr(i)

res = encrypt(charset)

d = dict()
for i in range(len(res)//12):
    s = res[i*12+8:i*12+12]
    if s not in d.keys():
        d[s] = list()
    d[s].append(charset[i])
    

flag = ''
for i in range(len(a)):
    x = int(a[i], 2)
    s = set()
    for j in range(8):
        s.add(chr(x ^ 1<<j))
    y = b[i]
    inter = s.intersection(set(d[y]))
    flag += str(inter)[2] if len(inter) > 0 else chr(x)

print(flag)
```

    bcactf{yumMY-y311OWC4ke-x7CwKqQc5fLquE51V-jMUA-aG9sYS1jb21vLWVzdGFz}