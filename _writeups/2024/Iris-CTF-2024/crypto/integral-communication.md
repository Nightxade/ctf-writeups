---
layout: writeup
category: Iris-CTF-2024
chall_description: N/A
points: 197
solves: 82
tags: crypto aes aes-cbc oracle json
date: 2024-12-7
comments: false
---

I've found this secret communication system running on a server. Unfortunately it uses AES so there's not much I can do.  
`nc integral-communication.chal.irisc.tf 10103`  
[integral-communication.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/integral-communication.tar.gz)  

---

We're provided a single source file for the challenge. Here it is:  

```py
from json import JSONDecodeError, loads, dumps
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

with open("flag") as f:
    flag = f.readline()

key = get_random_bytes(16)


def encrypt(plaintext: bytes) -> (bytes, bytes):
    iv = get_random_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    print("IV:", hexlify(iv).decode())
    return iv, aes.encrypt(plaintext)


def decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(ciphertext)


def create_command(message: str) -> (str, str):
    payload = {"from": "guest", "act": "echo", "msg": message}
    payload = dumps(payload).encode()
    while len(payload) % 16 != 0:
        payload += b'\x00'
    iv, payload = encrypt(payload)
    return hexlify(iv).decode('utf-8'), hexlify(payload).decode('utf-8')


def run_command(iv: bytes, command: str):
    try:
        iv = unhexlify(iv)
        command = unhexlify(command)
        command = decrypt(command, iv)

        while command.endswith(b'\x00') and len(command) > 0:
            command = command[:-1]
    except:
        print("Failed to decrypt")
        return

    try:
        command = command.decode()
        command = loads(command)
    except UnicodeDecodeError:
        print(f"Failed to decode UTF-8: {hexlify(command).decode('UTF-8')}")
        return
    except JSONDecodeError:
        print(f"Failed to decode JSON: {command}")
        return

    match command["act"]:
        case "echo":
            msg = command['msg']
            print(f"You received the following message: {msg}")
        case "flag":
            if command["from"] == "admin":
                print(f"Congratulations! The flag is: {flag}")
            else:
                print("You don't have permissions to perform this action")
        case action:
            print(f"Invalid action {action}")


def show_prompt():
    print("-" * 75)
    print("1. Create command")
    print("2. Run command")
    print("3. Exit")
    print("-" * 75)

    try:
        sel = input("> ")
        sel = int(sel)

        match sel:
            case 1:
                msg = input("Please enter your message: ")
                iv, command = create_command(msg)
                print(f"IV: {iv}")
                print(f"Command: {command}")
            case 2:
                iv = input("IV: ")
                command = input("Command: ")
                run_command(iv, command)
            case 3:
                exit(0)
            case _:
                print("Invalid selection")
                return
    except ValueError:
        print("Invalid selection")
    except:
        print("Unknown error")


if __name__ == "__main__":
    while True:
        show_prompt()
```

Essentially, we are provided a service that will "create" a command by encrypting a JSON object where only the "message" part of the object is user-controlled. We can also "run" a command by providing it an IV and ciphertext, which the service will accordingly decrypt to figure out what output to return.  

In order to win, we need to modify the JSON object such that `"from": "guest"` becomes `"from": "admin"` and `"act": "echo"` becomes `"act": "flag"`.  

Hm. It seems like we can't modify the rest of the JSON object at all, right?  

I tried sending a JSON object in the "message" field, but it obviously didn't work. So we likely need to actually modify the JSON object that results from the AES decryption. Luckily, I remembered doing a similar challenge on CryptoHack a while back. [This one](https://aes.cryptohack.org/flipping_cookie/) specifically. Since I already solved it, I just took a look at some of the solutions for the challenge. If you want to solve that challenge first, go try it and come back later for the rest of the writeup.  

Essentially, the method to solving the CryptoHack challenge involves modifying the IV that you send to the AES CBC decryption oracle. Understanding why this works requires a bit of background knowledge in AES CBC mode. [This site](https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/) provides a great visual of the process.  

But, essentially, to decrypt in AES CBC, the first block of 16 bytes is passed through regular AES ECB decryption, and then it is XORed with the IV, i.e. the initialization vector. Then, the next block of 16 bytes is passed through AES ECB decryption, and then it is XORed with the **previous** ciphertext block of 16 bytes. From then on, the next block of 16 bytes is always decrypted with AES ECB and then XORed with the previous ciphertext block of 16 bytes.  

So, in the CryptoHack challenge, the idea was to modify the IV to change the decrypted plaintext. See below on why this works:  

$$pt = AESdecrypt(ct) \oplus forgedIV$$  
$$forgedIV = iv \oplus pt \oplus injection$$  
$$pt = AESdecrypt(ct) \oplus iv \oplus pt \oplus injection$$  
$$pt \oplus (pt \oplus injection) = AESdecrypt(ct) \oplus iv \oplus pt \oplus injection \oplus (pt \oplus injection)$$  
$$injection = AESdecrypt(ct) \oplus iv$$  

And just like that, by injecting our forged IV, we have effectively replaced the original plaintext with our injected plaintext.  

In this challenge, we can use a similar technique to modify the decrypted plaintext! Unfortunately, we're not quite done yet.  

Our initial command will look something like this: `{"from": "guest", "act": "echo", "msg": ""}`  

Because the length of the message is greater than the 16-byte block length of AES, it actually reveals a flaw in our method. The IV has essentially no effect on the rest of the decrypted plaintext. Since AES CBC's encrypted blocks, except the very first block, are decrypted without the use of the IV, we cannot modify those blocks' plaintexts. And, unfortunately for us, that means we cannot modify `echo` to `flag` in this challenge.  

So how can we modify past the first 16 bytes? Well, there's a another exploit within this challenge cleverly hidden as an error message. Take a look at this section of the source file:  

```py
except UnicodeDecodeError:
    print(f"Failed to decode UTF-8: {hexlify(command).decode('UTF-8')}")
    return
```

If the service fails to decode the decrypted plaintext to UTF-8, it will actually tell us what the decrypted plaintext it tried to decode was. Conveniently, it also does not end the service, as the service continues prompting us for what we want to do.  

This is a key vulnerability. Remember how the second encrypted block is, at the end of the decryption process, XORed with the previous encrypted block? We can exploit that in the same way we exploited the IV, by modifying the first encrypted block to get the string we want, i.e. changing `echo` to `flag`.  

After that, the first encrypted block won't decrypt properly. But that's okay, because it tells us exactly what the end result of the decryption is! Knowing the end result of the decryption, we can just modify the IV, which, remember, is XORed with the first encrypted block after it is decrypted with AES ECB, so that it produces the right JSON format and changes the value of `guest` to `admin`.  

So we can break our solution down to 3 steps:  

1. Create initial command
2. Forge first 16 bytes of command to change "echo" to "flag"
3. Use the error message to forge IV to "fix" first 16 bytes of message and change "guest" to "admin"

Here is the implementation:  

```py
from pwn import *
from Crypto.Util.strxor import strxor
import binascii

p = remote('integral-communication.chal.irisc.tf', 10103)

# Step 1: Create initial command
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b': ', b'\n')
p.recvuntil(b': ')
iv = p.recvuntil(b'\n')[:-1]
p.recvuntil(b': ')
p.recvuntil(b': ')
cmd = p.recvuntil(b'\n')[:-1].decode('ascii')

cmd = binascii.unhexlify(cmd) # command = "{"from": "guest", "act": "echo", "msg": ""}"

# Step 2: Forge first 16 bytes of command to change "echo" to "flag"
forged_cmd_part = strxor(cmd[:16], b'\x00' * 10 + strxor(b'echo', b'flag') + b'\x00' * 2)
forged_cmd = binascii.hexlify(forged_cmd_part + cmd[16:])

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b': ', iv)
p.sendlineafter(b': ', forged_cmd)

# Step 3: Use error message telling us the decrypted message to forge iv to fix first 16 bytes of message and change "guest" to "admin"
p.recvuntil(b': ')
decrypted_cmd = p.recvuntil(b'\n')[:-1]
print(decrypted_cmd)
cmd_block1 = binascii.unhexlify(decrypted_cmd[:32])
print(decrypted_cmd[:32])
forged_iv = strxor(binascii.unhexlify(iv), strxor(cmd_block1, b'{"from": "admin"'))
forged_iv = binascii.hexlify(forged_iv)

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b': ', forged_iv)
p.sendlineafter(b': ', forged_cmd)

p.interactive()
```

And here is the flag!  

    irisctf{cbc_d03s_n07_m34n_1n73gr1ty}