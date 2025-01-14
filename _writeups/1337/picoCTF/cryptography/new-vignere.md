---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/hPYKzpI.png
points: 300
solves: 804
tags: crypto crypto/vigenere crypto/bits
date: 1337-01-01
comments: false
---

Another slight twist on a classic, see if you can recover the flag. (Wrap with picoCTF{}) `ioffdcjbfjmcifelcaloifgcjecgpgiebpfeiafhgajafkmlfcbpfbioflgcmacg` [new_vignere.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/new_vignere.py)  


---

We’re given a file, `new_vignere.py`, and a ciphertext, `ioffdcjbfjmcifelcaloifgcjecgpgiebpfeiafhgajafkmlfcbpfbioflgcmacg`.  

Here’s the file:  
```py
import string


LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]


def b16_encode(plain):
    enc = ""
    for c in plain:
        binary = "{0:08b}".format(ord(c))
        enc += ALPHABET[int(binary[:4], 2)]
        enc += ALPHABET[int(binary[4:], 2)]
    return enc


def shift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 + t2) % len(ALPHABET)]


flag = "redacted"
assert all([c in "abcdef0123456789" for c in flag])


key = "redacted"
assert all([k in ALPHABET for k in key]) and len(key) < 15


b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
    enc += shift(c, key[i % len(key)])
print(enc)
```

Let’s break down the important parts.  

Firstly, there are given restrictions to the possible character sets for the flag and the key.  
- The flag is all hex characters [0-9a-f].
- The key can contain the first 16 chars of lowercase alphabet and has a length of less than 15 characters.

Secondly, we are given two functions – `b16_encode` and `shift`.  

Before we demonstrate what each function does, keep in mind that each function is easily reversible, which clarifies that the goal of this challenge is probably to figure out the key and decrypt from there.  

- `shift(c, k)` is pretty clear on what it does – it’s just an implementation of a regular Vigenere’s cipher.
- `b16_encode(plain)` seems to be the new part of this cipher. Rather than breaking this down, I figured I might as well just try using it to see how it works!

```py
test = '0123456789abcdef'
testenc = b16_encode(test)
for i in range(0, len(testenc), 2): print(testenc[i:i+2], end=' ')
print()
```

Since we know that the flag has only hex characters, I only tested those. I then used the function on the whole string and split it into segments of length 2, given that the function seemed to be returning two characters for every character.  

This was the resulting output:  

`da db dc dd de df dg dh di dj gb gc gd ge gf gg`

From this, I realized a key detail of this function – the first character of each pair must be `d` or `g`. This is a more restrictive detail about the ciphertext that we can use to our advantage!  

Okay… what next? Well, since we know the first character of each pair must be `d` or `g`, why don’t we take a look at the first character of each segment of length 2 in the ciphertext? Though you might think that the fact that this ciphertext has already been encrypted with Vigenere’s with the key might obscure any important details, we know that the length of the key is *less than 15* – therefore, it couldn’t have obscured all the details, there definitely should be some patterns.  

In particular, there might be a pattern that reveals the length of the key. The crucial idea is that `d` and `g` have an offset of 3 between them in their ASCII codes. Therefore, if we can look for a suspicious repeated pattern of numbers that maintains an offset of 0 or 3 for each character with regards to the previous pattern, we can figure out the length of the key!  

It’s a bit confusing to think about, so let me show you how to do it instead.  

First, we extract the first character of each segment of length 2 from the cipher text:  
```py
for i in range(0, len(enc), 2):
    print(ord(enc[i]) - LOWERCASE_OFFSET, end=' ')
print()
```

This outputs the following:  

`8 5 3 9 5 12 8 4 2 11 8 6 9 2 15 8 1 5 8 5 6 9 5 12 5 1 5 8 5 6 12 2`

Immediately, what caught my eyes were the following patterns:  

`8 5 3 9 5 12` seemed to match up almost perfectly with `8 5 6 9 5 12`. The only difference is that the 3 became a 6. But, remember, `d` and `g` have an ASCII code offset of 3 between them, so this can be explained as one of them being `d` and the other being `g` before encryption with the key. However, with these two suspicious strings being so similar, I hypothesized that this was probably the start of the key!  

Only problem was, the offset between these two strings was too large – 18 in terms of the number sequence and 36 in the actual ciphertext (since each number corresponds to a segment of length 2). Well, if the offset is 36, the key length must be a factor of 36 – otherwise it would never have ended up like that. I’m going to skip directly to 9 as the factor because it doesn't take too long to try others like 12 and realize they don’t work.  

To see why 9 is right, let’s first separate the number sequences into segments of length 9. The reason we separate it into segments of length 9 is because each of the numbers occurs at an even index. If the key is an odd length, the second occurrence of it won’t align in the same places as the previous occurrence. Therefore, the third occurrence will be when the pattern restarts, as it aligns back to the same places as the first occurrence. (Also, with even keys, you could separate it into segments of length_of_key/2. But since 9 is odd, you can’t).  

|8|5|3|9|5|12|8|4|2|
|11|8|6|9|2|15|8|1|5|
|8|5|6|9|5|12|5|1|5|
|8|5|6|12|2|

Hey, would you look at that! If you notice, in each column, there are always at most two integer values, and these two values are always exactly 3 apart. That means 9 is likely our key length. How can we use that knowledge to figure out our key?  

Well, with our sequence of number values, we can first figure out which values should be `d` and `g`. The higher should be `g`, and the lower should be `d`. This is because, for each plaintext character where we added the same key character in Vigenere’s, the offset between the letters’ ASCII codes is kept constant. Therefore, the higher values must be g, and vice versa.  

I’ll only write out the corresponding values of the first row, and you’ll see why soon.  

`d d d d g d g g d`
Now that we know the first 9 characters, we can figure out half the key...right?  

Actually, it’s not just half. It’s the entire key. Because, remember, although we separated our sequence of numbers into segments of length 9 to figure out our key, these segments aren’t actually length 9 in the plaintext! As we discussed previously, if the key is an odd length, the second occurrence of the key won’t align with the same places as the previous occurrence. See below: (key is 0-indexed)  

|0|1|2|3|4|5|6|7|8|0|1|2|3|4|5|6|7|8|
|d| |d| |d| |d| |g| |d| |g| |g| |d| |

Notice how, in the first occurrence of the key, the d/g value always falls on an even index of the key, while in the second occurrence, the d/g value always falls on an odd index of the key.  

Thus, with just the first row, and the first 18 characters of the ciphertext, we should just be able to figure out the key! All we have to do now is reverse the shift(c, k) function and use that to figure out the key byte-by-byte by using the character in the encrypted string as c and the character it should be (d/g) as k. See the following implementation:  

```py
def revshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]


key = "" # 0-indexed
key += revshift(enc[0], 'd')
key += revshift(enc[10], 'd')
key += revshift(enc[2], 'd')
key += revshift(enc[12], 'g')
key += revshift(enc[4], 'd')
key += revshift(enc[14], 'g')
key += revshift(enc[6], 'd')
key += revshift(enc[16], 'd')
key += revshift(enc[8], 'g')
```

This gives us our key, and now all we have to do is reverse the b16_encode function to get the flag!  

```py
def b16_decode(plain):
    dec = ""
    for i in range(0, len(plain), 2):
        bin1 = "{0:04b}".format(ALPHABET.index(plain[i]))
        bin2 = "{0:04b}".format(ALPHABET.index(plain[i + 1]))
        dec += chr(int((bin1 + bin2), 2))
    return dec


dec = ""
for i, c in enumerate(enc):
    dec += revshift(c, key[i % len(key)])
print(b16_decode(dec))
```

    picoCTF{5342d0ee1ecd51dd9e75b1e929b59da1}
