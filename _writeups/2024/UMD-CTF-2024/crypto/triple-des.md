---
layout: writeup
category: UMD-CTF-2024
chall_description:
points: 484
solves: 20
tags: crypto crypto/des crypto/3des crypto/padding-oracle
date: 2024-4-28
comments: false
---

Before the Kwisatz Haderach, the Bene Gesserit used this oracle to predict the future.

`nc challs.umdctf.io 32333`

[tripledes.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UMD-CTF-2024/tripledes.py)  

---

We're given a Python source file and a service to connect to. Here's the source:  

```py
#!/usr/local/bin/python
from os import urandom
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex(open("key.txt", "r").read())
keys = [key[i:i+8] for i in range(0, len(key), 8)]
flag = open("flag.txt", "rb").read()

enc = pad(flag, 8)
for i in range(3):
	cipher = DES.new(keys[i], DES.MODE_CBC)
	enc = cipher.iv + cipher.encrypt(enc)
print("Here's the encrypted flag:", enc.hex())

while 1:
	print("Give us an encrypted text and we'll tell you if it's valid!")
	enc = input()
	try: enc = bytes.fromhex(enc)
	except:
		print("no")
		break
	if len(enc) % 8 != 0 or len(enc) < 32:
		print("no")
		break
	try:
		for i in range(3):
			iv, enc = enc[:8], enc[8:]
			cipher = DES.new(keys[2-i], DES.MODE_CBC, iv=iv)
			enc = cipher.decrypt(enc)
		dec = unpad(enc, 8)
		print("yes")
	except:
		print("no")
```

So, this seems like some sort of variant of triple DES, although decryption is replaced by encryption in the second step.  

I did some quick research on whether or not replacing the second step with encryption did anything, but quickly found that using decryption as the second step is only to allow users that used single DES to encrypt a ciphertext to decrypt using 3DES with the key repeated 3 times.  

Thus, this essentially turned the problem into a padding oracle attack.  

Padding oracles occur when an attacker is able to query a ciphertext and the oracle will inform the attacker whether or not the decrypted plaintext is properly padded. In this case, PKCS#7 padding is used. PKCS#7 padding is quite simple. If the plaintext is 1 byte off of the required block size, it will pad it with 1 byte of b'\x01'. If it is 2 bytes off, it will pad it with 2 bytes of b'\x02'. And so on and so forth.  

So, in this case, the oracle will check if the decrypted plaintext has valid PKCS#7 padding (which really only matters with the last block of the plaintext) and inform the attacker of its validity.  

Padding oracle attacks are a very standard crypto attack. If you did crypto/padding oracle (the easier padding oracle), you'll know how it works. For those that don't, I recommend reading [this article](https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/), which gives a great explanation of how to attack an oracle with AES CBC using PKCS#7 padding. (Make sure you understand the standard block cipher padding oracle attack before moving on! Otherwise, you might not understand the rest of the explanation).  

However, there's a major difference between AES CBC and 3DES CBC. With AES, the single encryption step makes it easy to modify the IV to figure out the bytes of the plaintext because only one decryption step occurs. However, in 3DES, 3 decryption steps occur, and additionally, 3 different IVs are used and they depend on the previous decryption step.  

So, how can we even attack this padding oracle?  

Well, in our padding oracle attack, we first want to set the last byte of a plaintext block to b'\x01'. Note that we can isolate just the first plaintext block and focus on just setting the last byte of that block to b'\x01'.  

Obviously, we can't really modify the pre-decryption block, as doing so would not help us because it would change the decrypted plaintext from the flag to some nonsense. Instead, we need to repeatedly change the final (third) IV until the last byte becomes `flag[-1] ^ b'\x01'`. Note that flag[-1], in this case, represents the last byte of the first plaintext block.  

But how do we change the final IV while still knowing how exactly it changed? Because we need to know how it changed in order to retrieve the flag.  

My first thought was actually to just XOR the last byte of the initial (first) 8-byte IV. It turns out that this actually is the correct first step in decrypting the first plaintext block!  

The reason this works is because the first IV actually directly affects the final IV. Check out the following diagram of the process:  

<img src="https://i.imgur.com/GumZJgM.png" alt="3DES diagram" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

Let's walk through what would happen if we XORed the last byte of the IV in the very first step of decryption. In the following steps, any references to an IV refers only to the last byte:  

1. First IV = IV1 ^ 0x1, where IV1 is the original first IV  
2. Second IV = decrypt(Block 1 of step 1) ^ IV1 ^ 0x1 = IV2 ^ 0x1, where IV2 is the original second IV  
3. Third IV = decrypt(Block 1 of step 2) ^ IV2 ^ 0x1 = IV3 ^ 0x1, where IV3 is the original third IV  
4. New plaintext 1 = decrypt(Block 1 of step 3) ^ IV3 ^ 0x1 = PT ^ 0x1, where PT is the original plaintext  

Thus, we can essentially brute force the last byte of the IV until the oracle tells us we have valid padding by changing what we XOR the last byte of the first IV with. Then, that byte of the flag is `our byte ^ 0x1`, since `PT ^ our byte` returned 0x1 to make valid PKCS#7 padding.  

We can extend this to the rest of the bytes of the IV, changing our payload to make the last bytes valid PKCS#7 padding based on our knowledge of the last bytes of that block of the plaintext and then brute forcing the next byte.  

Here's a short script that does the aforementiond process for the first plaintext block:  

```py
from Crypto.Util.strxor import strxor
from binascii import unhexlify
from pwn import *

p = remote('challs.umdctf.io', 32333)
flag = p.recvline()[:-1].split(b' ')[-1]

def send(b: bytes):
    p.recvuntil(b'!\n')
    p.sendline(b)
    if b'yes' in p.recvline():
        return True
    return False

pt = b''
for j in range(8):
    for i in range(128, -1, -1):
        payload = hexlify(strxor(unhexlify(flag[:64]), b'\x00'*(7 - j) + i.to_bytes(1, 'big') + strxor(pt, (j+1).to_bytes(1, 'big')*len(pt)) + b'\x00' * (24)))
        if send(payload):
            pt = chr(i ^ (j + 1)).encode() + pt
            break
    print(pt)
```

However, it's a figuring out the rest of the plaintext blocks can be a bit more difficult. After all, modifying the first IV doesn't actually help change the other plaintext blocks besides the first one, and modifying any block besides the very first IV block is pretty much useless to us because the DES decryption step makes it so that we will have no knowledge of how the byte has changed, and thus, whenever we are able to achieve valid padding in the second plaintext block or some other plaintext block, we will not know how to retrieve the flag byte from this knowledge.  

After ~20 minutes of thinking, I realized something crucial. The main reason it's useless to modify the non-IV blocks is because the DES decryption essentially makes it impossible for us to recover the flag from the padding oracle. However, what if we got rid of the DES decryption? Now, the only block that doesn't get DES decrypted is the IV block. However, the convenient thing is that getting rid of the original IV block entirely means that the next block of ciphertext now acts as the new IV, essentially. And decryption for everything else actually works out perfectly fine.  

Therefore, what we can do is actually get rid of the first block of ciphertext (the IV) entirely, and use the next block as our IV. We can then extend our whole ciphertext to the next block, so that we continue recovering the next plaintext block. We can repeat this process until we are left with no more plaintext blocks to recover. You may want to refer back to the previous diagram image, shown here, to confirm that using Block 1 in the diagram as the new IV (essentially getting rid of all the IVs in each row and Plain 1 as well) will be able to produce a similar change as described for attacking first plaintext block.  

<img src="https://i.imgur.com/GumZJgM.png" alt="3DES diagram" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

Thus, knowing this, we can now create the final implementaion script:  

```py
from pwn import *
from Crypto.Util.strxor import strxor
from binascii import *
from tqdm import trange

p = remote('challs.umdctf.io', 32333)
flag = p.recvline()[:-1].split(b' ')[-1]

def send(b: bytes):
    p.recvuntil(b'!\n')
    p.sendline(b)
    if b'yes' in p.recvline():
        return True
    return False

blocks = [flag[i:i+16] for i in range(48, len(flag), 16)]
dec = b''
for ind in range(len(blocks)):
    pt = b''
    for j in range(8):
        for i in range(128, -1, -1):
            payload = hexlify(strxor(unhexlify(flag[16*ind:16*(ind+4)]), b'\x00'*(7 - j) + i.to_bytes(1, 'big') + strxor(pt, (j+1).to_bytes(1, 'big')*len(pt)) + b'\x00' * (24)))
            if send(payload):
                pt = chr(i ^ (j + 1)).encode() + pt
                break
        print(pt)
    dec += pt
    print(dec)
```

Run the script to get the flag!  

(Sidenote: make sure to iterate backwards in the loop with range(128, -1, -1) to save time, otherwise the server throws and EOF error).  

    UMDCTF{padding_oracle_with_extra_steps?}