---
layout: writeup
category: BCA-CTF-2024
chall_description:
points: 100
solves: 224
tags: crypto rsa hastad-broadcast-attack
date: 2024-06-12
comments: false
---

I made an rsa encrypter to send my messages but it seems to be inconsistent...

`nc challs.bcactf.com 31452`

[rsa_encrypter.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/rsa_encrypter.py)  

---

Here's the Python source:  

```py
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


message = open("./flag.txt").read().encode('utf-8')  


def encode():
    n = getPrime(512)*getPrime(512)
    ciphertext = pow(bytes_to_long(message), 3, n)
    return (ciphertext, n)

print("Return format: (ciphertext, modulus)")
print(encode())
sent = input("Did you recieve the message? (y/n) ")
while sent=='n':
    print(encode())
    sent = input("How about now? (y/n) ")
print("Message acknowledged.")
```

This is simply a well-known attack called Hastad's Broadcast Attack. [This site](https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Hastad-Broadcast/README.md) has a great explanation.  

Anyways, just copy an online script :)  

```py
from pwn import *
from Crypto.Util.number import *

# p = remote('34.23.70.45', 32666)

# p.interactive()

c1,n1 = (44317689234766222409459683128460365714927471231200151486241736233764559366728172509091444098547659469186593782379826431342635457488117027250664728259837242373815742582202609671156038966765071924307602244527839186294678942845558062174128818694767893396646308383408305089266354657192186955284216255445470987666, 139385557109658948744003393444636097209450643591457873028800214090305049987672711019778948146032604372376711963281806271960244118789018311793363197664654272345090500662282756747196229143656535223238770565612321852085607261903056263179675859007824748000946183666449384887098658142494238777266437884721452499447)
c2,n2 = (16949655456649793800119506062607989523816125155591604419445207971956739379261417376351468876985609760808917567914467480794944748500109612034722190629867823251026086358949621436960582783553139412591998210251752720630557704069647809634778080075258351126690537183000359568049448700049718595130288083497914288491, 124007278590849315300540755220279021413333511194971098290025826161894764793024259170594769977259770384127911470237873501266252899043763583282549332899521371672292034271988907953046355140375407860049062770434280195671811816357747251788322234748652243868099141855866328895977586450200839907991371068693954734481)
c3,n3 = (34428010899373979201455723407620401185909229630591810128729543663548847117726354673078654902672570740266296245666958061207479109277447098904910625422524622813388447426944021311228871009856146990464305974824488333974207686988306232972909005860063564508632006522287769737313250008318041840995101742115813115707, 137116733942074231735293491207386909555282710327796574729475387248648104319504808487955869432373740153377958609476155528197660736000250553474645300587281244732780707582547568694481698362695097670552706304376837935295443464792616007877675669723803347365425633649643110625619731619371076659280185882599821727157)
e = 3

import gmpy2
gmpy2.get_context().precision = 4096

from binascii import unhexlify
from functools import reduce
from gmpy2 import root

# Håstad's Broadcast Attack
# https://id0-rsa.pub/problem/11/

# Resources
# https://en.wikipedia.org/wiki/Coppersmith%27s_Attack
# https://github.com/sigh/Python-Math/blob/master/ntheory.py

EXPONENT = 3

CIPHERTEXT_1 = "ciphertext.1"
CIPHERTEXT_2 = "ciphertext.2"
CIPHERTEXT_3 = "ciphertext.3"

MODULUS_1 = "modulus.1"
MODULUS_2 = "modulus.2"
MODULUS_3 = "modulus.3"


def chinese_remainder_theorem(items):
    # Determine N, the product of all n_i
    N = 1
    for a, n in items:
        N *= n

    # Find the solution (mod N)
    result = 0
    for a, n in items:
        m = N // n
        r, s, d = extended_gcd(n, m)
        if d != 1:
            raise "Input not pairwise co-prime"
        result += a * s * m

    # Make sure we return the canonical solution.
    return result % N


def extended_gcd(a, b):
    x, y = 0, 1
    lastx, lasty = 1, 0

    while b:
        a, (q, b) = b, divmod(a, b)
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y

    return (lastx, lasty, a)


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1


def get_value(filename):
    with open(filename) as f:
        value = f.readline()
    return int(value, 16)

if __name__ == '__main__':

    C = chinese_remainder_theorem([(c1, n1), (c2, n2), (c3, n3)])
    M = int(root(C, 3))

    M = hex(M)[2:]
    print(unhexlify(M))
```

    bcactf{those_were_some_rather_large_numbersosvhb9wrp8ghed}