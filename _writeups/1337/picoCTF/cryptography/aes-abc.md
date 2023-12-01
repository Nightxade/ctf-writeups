---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/3wn4izQ.png
points: 400
solves: 1243
tags: crypto aes
date: 1337-01-01
comments: false
---

AES-ECB is bad, so I rolled my own cipher block chaining mechanism - Addition Block Chaining! You can find the source here: [aes-abc.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/aes-abc.py). The AES-ABC flag is [body.enc.ppm](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/aes-body.enc.ppm)

---

We’re given two files, `aes-abc.py` and `body.enc.ppm`. Here is `aes-abc.py`:  
```py
#!/usr/bin/env python

from Crypto.Cipher import AES
from key import KEY
import os
import math


BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))




def to_bytes(n):
    s = hex(n)
    s_n = s[2:]
    if 'L' in s_n:
        s_n = s_n.replace('L', '')
    if len(s_n) % 2 != 0:
        s_n = '0' + s_n
    decoded = s_n.decode('hex')


    pad = (len(decoded) % BLOCK_SIZE)
    if pad != 0:
        decoded = "\0" * (BLOCK_SIZE - pad) + decoded
    return decoded




def remove_line(s):
    # returns the header line, and the rest of the file
    return s[:s.index('\n') + 1], s[s.index('\n')+1:]




def parse_header_ppm(f):
    data = f.read()


    header = ""


    for i in range(3):
        header_i, data = remove_line(data)
        header += header_i


    return header, data
       


def pad(pt):
    padding = BLOCK_SIZE - len(pt) % BLOCK_SIZE
    return pt + (chr(padding) * padding)




def aes_abc_encrypt(pt):
    cipher = AES.new(KEY, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt))


    blocks = [ct[i * BLOCK_SIZE:(i+1) * BLOCK_SIZE] for i in range(len(ct) / BLOCK_SIZE)]
    iv = os.urandom(16)
    blocks.insert(0, iv)
   
    for i in range(len(blocks) - 1):
        prev_blk = int(blocks[i].encode('hex'), 16)
        curr_blk = int(blocks[i+1].encode('hex'), 16)


        n_curr_blk = (prev_blk + curr_blk) % UMAX
        blocks[i+1] = to_bytes(n_curr_blk)


    ct_abc = "".join(blocks)
 
    return iv, ct_abc, ct




if __name__=="__main__":
    with open('flag.ppm', 'rb') as f:
        header, data = parse_header_ppm(f)
   
    iv, c_img, ct = aes_abc_encrypt(data)


    with open('body.enc.ppm', 'wb') as fw:
        fw.write(header)
        fw.write(c_img)
```

Before beginning, let’s first clarify what a .ppm file is. It is essentially an image file, so we are looking to somehow decrypt `body.enc.ppm` to get another .ppm file that should contain the flag.  

Now let’s take a look at the code.  

Most of it is unimportant, as it details functions to help with encryption and data parsing. The only part worth noting is that, of the items returned from `aes_abc_encrypt(data)`, we only receive `c_img`, which is presumably the ciphertext after AES-ABC encryption.  

The key part of this code is located in the `aes_abc_encrypt()` function. Let’s break it down step by step.  

<ol>
<li>An AES ECB cipher is created with an unknown key and used to encrypt the padded version of the data.</li>
<li>The resulting ciphertext is split up into blocks of size 16, the usual for AES.</li>
<li>A random IV is generated and inserted at index 0 of the blocks array.</li>
<li>A for loop is created that will loop from 0 to less than len(blocks) - 1 with index i.
    <ol>
        <li>We get prev_blk as the ith index of blocks and curr_blk as the (current index + 1)th index of blocks.</li>
        <li>n_curr_blk is set equal to (prev_blk + curr_blk) % UMAX</li>
        <li>blocks[i + 1] is set to n_curr_blk</li>
    </ol>
</li>
<li>ct_abc is set to the concatenation of the blocks and returned.</li>
</ol>

For those of you familiar with AES challenges, you may notice this is highly similar to AES CBC.  

For those unaware of what AES CBC is, I would recommend checking out [this site](https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/) that explains the basics. In short, though, all you need to know is that the ciphertext of the previous block is XORed with the plaintext of the current block before encryption.  

This “AES ABC” encryption is quite similar, but with a key weakness. Notice how, in AES CBC, the previous ciphertext block is XORed with the plaintext before encryption. With this AES ABC mode, the previous ciphertext block is XORed with the ciphertext, i.e. after encryption. So, it should be pretty trivial to reverse this addition block chaining part and get the ciphertext if only AES ECB was used by looping backwards over the ciphertext in `body.enc.ppm` and subtracting to get the original ciphertext block. It may be helpful for you to draw out the encryption process much like they do in the aforementioned site to understand this!  

However, there’s still one more problem. We don’t know the key, so how can we decrypt this AES ECB? Isn’t it impossible?  

And yes, you’d be correct. Without the key, it’s pretty infeasible to decrypt the ciphertext. Thankfully, though, we don’t need to!  

Because ECB encrypts each block of 16 bytes individually, it doesn’t properly obscure image structure. The [PicoPrimer](https://primer.picoctf.com/#_modern_cryptography) provides a good example and explanation of this.  

Therefore, it is suitable to simply reverse the addition block chaining and load our resultant .ppm file into an online .ppm viewer to get the flag!  

    picoCTF{d0Nt_r0ll_yoUr_0wN_aES}

Implementation of reversing the addition block chaining:  
```py
import os
import math
import binascii


BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))


def remove_line(s):
        # returns the header line, and the rest of the file
        return s[:s.index(b'\n') + 1], s[s.index(b'\n')+1:]


def parse_header_ppm(f):
        data = f.read()


        header = b""


        for i in range(3):
                header_i, data = remove_line(data)
                header += header_i


        return header, data


f = open('crypto/AES-ABC/body.enc.ppm', 'rb')
header, ct = parse_header_ppm(f)


print(header)


blocks = [ct[i * BLOCK_SIZE:(i+1) * BLOCK_SIZE] for i in range(len(ct) // BLOCK_SIZE)]
for i in range(len(blocks) - 2, 0, -1):
        prev_blk = int(binascii.hexlify(blocks[i]), 16)
        curr_blk = int(binascii.hexlify(blocks[i+1]), 16)


        n_curr_blk = (curr_blk - prev_blk) % UMAX
        blocks[i + 1] = binascii.unhexlify("{:032x}".format(n_curr_blk))


n_ct = b"".join(blocks)


fw = open('crypto/AES-ABC/out.ppm', 'wb')
fw.write(header)
fw.write(n_ct)
```

Final image:
<img src="https://i.imgur.com/WJ0Jbhf.jpg" alt="AES ABC Flag Image" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>