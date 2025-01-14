---
layout: writeup
category: UT-CTF-2024
chall_description:
points: 912
solves: 91
tags: UT-CTF-2024 misc misc/credit-cards
date: 2024-4-1
comments: false
---

I've got some credit cards but I don't which ones are valid. Where did I get them? Uh, that's not important.

Oh, you'll probably need this: dae55498c432545826fb153885bcb06b

By mzone (@mzone on discord)

`nc puffer.utctf.live 8625`

---

Connect to the service. The service continuously queries, given a PAN, date, code, and cvv of a credit card, if the credit card is valid. One must get many consecutively right to receive the flag.  

The first, rather trivial check to do is to check that the date is valid. The date is in the format MMYY, so just check if the month is less than 13 and greater than 0.  

The second, also trivial check, is length checks. We just need to check that the date is of length 4 and that the code and cvv are length 3. The PAN also needs to be checked for length, but I ended up just not including it because it never was needed.  

With some research, we can quickly find the existence of something known as Luhn's algorithm. This is a way to validate a credit card's PAN. The algorithm follows as such:  

1. Beginning from the end of the PAN and traversing backwards, double every other digit.  
2. For every digit, add it to a sum variable. If the digit, however, after being doubled, is two digits, instead add the sum of those two digits.  
3. If the sum is divisible by 10, it is a valid credit card number.  

Here's a small example:  

PAN = 348745  
Step 1: 6, 4, 16, 7, 8, 5  
Step 2: 6 + 4 + (1 + 6) + 7 + 8 + 5 = 37  

Since the sum is not divisible by 10, it is *not* a valid credit card PAN.  

There are various online implementations of Luhn's algorithm, like [here](https://allwin-raju-12.medium.com/credit-card-number-validation-using-luhns-algorithm-in-python-c0ed2fac6234).  

The harder part of the problem was finding what to do with the rest of the information. I actually was not able to figure out the exact algorithm for this, but my teammate helped me out with this. 

Here's a quick outline of what we found.  

1. We need a 16-byte key to use for DES. Note that the provided hex string in the challenge description is 16 bytes, which, to us, was very indicative of this algorithm being correct.  

2. We also need a PAN, an expiration date equivalent to 4 numbers in MMYY format, and a 3 number service code.  

3. Concatenate the PAN, expiration date, and service code, and then pad the result with zeros until it's 32 bytes.  

4. Using DES ECB, encrypt the first 16 bytes of the data with the first 8 bytes of the key.  

5. XOR the result with the last 16 bytes of the data/  

6. Encrypt the result with the first 8 bytes of the key.  

7. Decrypt the result with the last 8 bytes of the key.  

8. Encrypt the result with the first 8 bytes of the key.  

9. The first three numeric digits from the hexlified bytes of the result is the CVV. (hexlified: A = 0x41).  

Thus, with this algorithm, we can use the rest of the information to confirm whether or not the CVV is correct.  

And that's it! All that's left is to implement it. See below:  

```py
from pwn import *
from Crypto.Cipher import DES
from binascii import *
from Crypto.Util.strxor import strxor
import string
from Crypto.Util.number import *

p = remote('puffer.utctf.live', 8625)
p.recvuntil(b'again.\n')
p.recvline()

# https://allwin-raju-12.medium.com/credit-card-number-validation-using-luhns-algorithm-in-python-c0ed2fac6234
def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = 0
    checksum += sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10

def pad(x):
    if len(x) == 32:
        return x
    x += (32 - len(x))*'0'
    return x

def cvv(pan, date, code, key='dae55498c432545826fb153885bcb06b'):
    m = pan + date + code
    m = pad(m)

    c1 = DES.new(unhexlify(key[:16]), mode=DES.MODE_ECB)
    c2 = DES.new(unhexlify(key[16:]), mode=DES.MODE_ECB)
    ct = c1.encrypt(unhexlify(m[:16]))
    ct = strxor(ct, unhexlify(m[16:]))
    ct = c1.encrypt(ct)
    ct = c2.decrypt(ct)
    ct = c1.encrypt(ct)
    ct = hexlify(ct)
    cvv = ''
    for i in ct:
        if i < 128 and chr(i) in string.digits:
            cvv += chr(i)
        if len(cvv) == 3:
            break
    return cvv

res_data = ''
while(True):
    req = p.recvline().decode('ascii')[:-1].split(',')
    try:
        p.recvline()
    except:
        break
    # print(req)

    data = []
    for i in req:
        data.append(i.split(' ')[-1])
    # print(data)

    res = 1
    if len(data[2]) != 3 or len(data[3]) != 3:
        # print('Code/CVV')
        res = 0
    if int(data[1][:2]) > 12 or int(data[1][:2]) < 1 or len(data[1]) != 4:
        # print('Date')
        res = 0
    s = luhn_checksum(int(data[0]))
    # print('\nLuhn:', s)
    if s % 10 != 0:
        # print('Luhn')
        res = 0

    c = cvv(data[0], data[1], data[2])
    if c != data[3]:
        # print('CVV')
        res = 0
    
    # print(res)
    res_data += str(res)
    p.sendline(str(res).encode())
    p.recvline()

print(long_to_bytes(int(res_data, 2)))
```

Run the script to get the flag!  

    utflag{hope_none_of_those_were_yours_lol}