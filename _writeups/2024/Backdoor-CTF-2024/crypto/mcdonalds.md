---
layout: writeup
category: Backdoor-CTF-2024
chall_description: 
points: 100
solves: 245
tags: crypto hash mac
date: 2024-12-24
comments: false
---

My friend has created his own hashing service and has given it to me to crack it, can you help me with it. He has promised me a burger for this as I like McDonald's so much , can you help me get some? please :) :)  

nc 34.42.147.172 8004  

Author: gr00t  

[server.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Backdoor-CTF-2024/server.py)  

---

We are provided `server.py`:  

```py
import hashlib
from typing import List

class CustomMAC:
    def __init__(self):
        self._internal_state = b""
        
    def update(self, message: bytes) -> None:
        if not self._internal_state:
            self._internal_state = self.get_key() + message
        else:
            self._internal_state += message
            
    def get_key(self) -> bytes:
        return open("key.txt", "rb").read().strip()
            
    def digest(self) -> bytes:
        return hashlib.sha256(self._internal_state).digest()[:8]

class TokenManager:
    def __init__(self):
        self._mac = CustomMAC()
        self._seen_tokens: List[bytes] = []
        
    def verify_and_store(self, message: bytes, token: bytes) -> bool:
        self._mac = CustomMAC()
        self._mac.update(message)
        expected_token = self._mac.digest()
        
        if token != expected_token:
            print(f"Invalid token! Expected token: {expected_token.hex()}")
            return False
            
        if token in self._seen_tokens:
            print("Token already used!")
            return False
            
        self._seen_tokens.append(token)
        return True

def main():
    print("Welcome to the Token Verification Challenge!")
    print("============================================")
    print("Rules:")
    print("1. Submit message-token pairs")
    print("2. Each token must be valid for its message")
    print("3. You cannot reuse tokens")
    print("4. Get 64 valid tokens accepted to win!")
    print("\nFormat: <hex-encoded-message> <hex-encoded-token>")
    print("Example: 48656c6c6f 1234567890abcdef")
    
    manager = TokenManager()
    successes = 0
    
    for i in range(128):
        try:
            print(f"\nAttempt {i+1}/128")
            print("Enter your message and token: ", end='')
            user_input = input().strip().split()
            
            if len(user_input) != 2:
                print("Invalid input format!")
                continue
                
            message = bytes.fromhex(user_input[0])
            token = bytes.fromhex(user_input[1])
            
            if manager.verify_and_store(message, token):
                successes += 1
                print(f"Success! {successes}/64 valid tokens verified")
                
                if successes >= 64:
                    print("\nCongratulations! You beat the challenge!")
                    with open("flag.txt", "r") as f:
                        print(f.read().strip())
                    break
            
        except Exception as e:
            print(f"Error: {str(e)}")
            continue
            
    if successes < 64:
        print("\nChallenge failed! Not enough valid tokens.")

if __name__ == "__main__":
    main()
```

The key vulnerability lies in the `verify_and_store()` function.  

There are a few characteristics of this function that make it vulnerable.  
1. `self._mac` is reinitialized every iteration, so the hash will always be computed on the concatenation of `key.txt` with the message `m`  
2. If the token is invalid, then the token is never added to `self._seen_tokens`.  
3. If the token is invalid, then the correct token is given to the user.  

Properties #2 and #3 mean that we can send a (message, invalid token) pair, and receive the correct token for that message. And due to property #1, that means that sending the new pair of (message, received token) will actually be correct!  

Therefore, since we're given 128 message attempts, it's as simple as sending 64 (message, invalid token) pairs, with all messages being distinct from each other, and then sending the corresponding 64 (message, received token) pairs. Here's the implementation of that:  

```py
from pwn import *
from tqdm import trange

def send_bad(m: bytes, t: bytes) -> bytes:
    p.recvuntil(b'token: ')
    p.sendline(m + b' ' + t)
    return p.recvline()[:-1].split(b' ')[-1]

def send_good(m: bytes, t: bytes):
    p.recvuntil(b'token: ')
    p.sendline(m + b' ' + t)

p = remote('34.42.147.172', 8004)

a = []
for i in trange(64):
    a.append(send_bad("{:02d}".format(i).encode(), b'00'))
assert len(set(a)) == len(a), len(set(a))
for i in trange(64):
    send_good("{:02d}".format(i).encode(), a[i])

p.interactive()
```

	flag{C0ngr4ts_0n_f1nd1ng_Th1s_H4sh_c0ll1s10ns_N0w_G0_h4v3_4_D0ubl3_Ch33s3_Burg3r}