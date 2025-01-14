---
layout: writeup
category: UT-CTF-2024
chall_description:
points: 908
solves: 95
tags: UT-CTF-2024 crypto crypto/signature crypto/forgery
date: 2024-4-1
comments: false
---

The s in rsa stands for secure.

By alex (@kyrili : not the isss officer - someone y'all don't know)

Contact jocelyn (@jocelyn3270 on discord)

`nc betta.utctf.live 4374`

---

<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>

Connect to the service. The service provides us with an N value and an e value that last for the entire instance. We are provided an oracle that will infinitely sign messages for us. Once we enter 0 into the program, the oracle will ask us to produce our own valid message and signature pair (such that the message has not been requested previously).  

Note that RSA signatures are calculated as follows:  

$$m^d\equiv s\;(mod\;N)$$  

And the receiver of the RSA signature can raise $$s$$ to the $$e$$ power to confirm that the message is actually from the owner of the RSA private key:  

$$s^e \equiv m^{ed} \equiv m\;(mod\;N)$$  

The goal of this challenge is known as a forgery attack, in which an attacker attempts to forge a valid message and signature pair, pretending to tbe owner of the RSA private key. In this case, the simplest forgery attack can be used. Here's why:  

1. Let's first query the oracle for the signatures of two distinct messages:  

$$m_1^d \equiv s_1\;(mod\;N)$$  
$$m_2^d \equiv s_2\;(mod\;N)$$  

2. Now, consider what would happen if we multiplied these two equations/congruence relations:  

$$m_1^d \cdot m_2^d \equiv s_1 \cdot s_2\;(mod\;N)$$  
$$(m_1 \cdot m_2)^d \equiv s_1 \cdot s_2\;(mod\;N)$$  

Note that we have now produced a valid message and signature pair! The product of $$m_1m_2$$ is the message that corresponds to the signature $$s_1s_2 \;(mod\;N)$$  

Therefore, in order to forge the signature, we can first query the oracle for the signatures for two messages (I used 2 and 3) and then, after sending 0 to terminate the oracle, send the result of $$m_1m_2$$ as the message and the result of $$s_1s_2\;(mod\;N)$$ as the signature to get the flag!  

Here's the implementation:  

```py
from pwn import *

p = remote("betta.utctf.live", 4374)

p.recvline()
p.recvline()
p.recvline()

m1 = 2
m2 = 3
n = int(p.recvline().decode('ascii')[:-1].split(' ')[-1])
p.recvuntil(b': ')
p.sendline(str(m1).encode())
s1 = int(p.recvline().decode('ascii')[:-1].split(' ')[-1])
p.recvuntil(b': ')
p.sendline(str(m2).encode())
s2 = int(p.recvline().decode('ascii')[:-1].split(' ')[-1])

m_forge = (m1*m2)%n
s_forge = (s1*s2)%n

p.recvuntil(b': ')
p.sendline(b'0')
p.recvline()
p.sendlineafter(b': ', str(m_forge).encode())
p.sendlineafter(b': ', str(s_forge).encode())
p.interactive()
```

Run the script to get the flag!  

    utflag{a1m05t_t3xtb00k_3x3rc153}