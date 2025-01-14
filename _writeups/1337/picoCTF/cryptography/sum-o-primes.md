---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/XL7nL4h.png
points: 400
solves: 1497
tags: crypto crypto/rsa
date: 1337-01-01
comments: false
---

We have so much faith in RSA we give you not just the product of the primes, but their sum as well!  
- [gen.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/sum-o-primes-gen.py)
- [output.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/sum-o-primes-output.txt)

---

We’re given two files, `gen.py` and `output.txt`. `gen.py` tells us that $$e=65537$$, while `output.txt` provides us the hex values of x, e, and n, where x is the sum of the two primes p and q.
`output.txt`:  
```
x = 1626a189dcb38ca6b8e9ee26623ab5c3c6cd7e4c7ff6726f4b03831ca48c617a056827c5763458d0aa7172650072b892649cc73f943f156b795ff5dd2fc9a53b140cf9c3ee2cbb8181d17bb0275f404b4090766f798ad156db7e71000e93db65f3e1bc7406532d0f509fbecf095ef215b4ad51f5e8ac765861e5f93808948bf72
n = 720d66204ec312d7f1bc688495d4585ec58520170b86ed3488c3f9c76407b7e9e466b82a282ba90d484698160f2e27f413b07cf8805d560abdffa977547d5fec3190a1ce284dfc8e92193f2f70590bf9c6e6d0ab449e35ef43ed20232b7f8686696125cde1f950230fbc6858392a3715c1b8a4947748b7fadd5cc921716ad5e0129c91ea88fceee140fb1c594606186afacb69143ef8f7b3b1aa2cc3206395c60e71ec0555dd15838d8a8395e8ccf9a4e4c4199ae0ab3f8af7ebc6605edc5ddd480be2d6c41e38618eba5822a1e566080877268802750de71e890ac865ebf87fdc290d9151e407dff4c97390c9e7388fd538e2716515cea2240f55963c2e0c21
c = 554b90eb12fbece709d7bf23ab91f9b52d71cd77fbf42f65d68623c2055d99956b9bcf2eaf14771fa5781fae86624e44b452a0f68768849faba1b9695ce353a17238a3e7040ee7aede68b35bf4b51daf0982653910b280ac98aad9a5b3c49d226e10b2e8660effc2cb2a553039bde527e42f1795bc078af6ed2928505be6df1ebe993f2ed8c10477dd5cc9f899d1e69b6512b71c732472dde521f5393c76b2f9fbed668560d4e50ca177dd14b923414549d688b20fab94dba7cad7b5a729941c772dc4a1db79b0e6a111d2d2e8998b4e2a272dc940a9dd4cf856faa5a2ee0cb6f36f0ce6edbb421697e517a4d589cc5a880eecf6fbf65e5f6a1a437b06e5ff9a
```

So this is what we know:  

$$p+q=x$$  

$$pq=n$$  

We also know that $$\phi(n)=(p-1)(q-1)=pq-p-q+1$$  

Wait… so isn’t $$\phi(n)=pq-(p+q)+1=n-x+1$$  

So we can just figure out $$\phi(n)$$ and then just use that value to figure out d and subsequently decrypt the flag!  
```py
from Crypto.Util.number import long_to_bytes

sum = "1626a189dcb38ca6b8e9ee26623ab5c3c6cd7e4c7ff6726f4b03831ca48c617a056827c5763458d0aa7172650072b892649cc73f943f156b795ff5dd2fc9a53b140cf9c3ee2cbb8181d17bb0275f404b4090766f798ad156db7e71000e93db65f3e1bc7406532d0f509fbecf095ef215b4ad51f5e8ac765861e5f93808948bf72"
n = "720d66204ec312d7f1bc688495d4585ec58520170b86ed3488c3f9c76407b7e9e466b82a282ba90d484698160f2e27f413b07cf8805d560abdffa977547d5fec3190a1ce284dfc8e92193f2f70590bf9c6e6d0ab449e35ef43ed20232b7f8686696125cde1f950230fbc6858392a3715c1b8a4947748b7fadd5cc921716ad5e0129c91ea88fceee140fb1c594606186afacb69143ef8f7b3b1aa2cc3206395c60e71ec0555dd15838d8a8395e8ccf9a4e4c4199ae0ab3f8af7ebc6605edc5ddd480be2d6c41e38618eba5822a1e566080877268802750de71e890ac865ebf87fdc290d9151e407dff4c97390c9e7388fd538e2716515cea2240f55963c2e0c21"
c = "554b90eb12fbece709d7bf23ab91f9b52d71cd77fbf42f65d68623c2055d99956b9bcf2eaf14771fa5781fae86624e44b452a0f68768849faba1b9695ce353a17238a3e7040ee7aede68b35bf4b51daf0982653910b280ac98aad9a5b3c49d226e10b2e8660effc2cb2a553039bde527e42f1795bc078af6ed2928505be6df1ebe993f2ed8c10477dd5cc9f899d1e69b6512b71c732472dde521f5393c76b2f9fbed668560d4e50ca177dd14b923414549d688b20fab94dba7cad7b5a729941c772dc4a1db79b0e6a111d2d2e8998b4e2a272dc940a9dd4cf856faa5a2ee0cb6f36f0ce6edbb421697e517a4d589cc5a880eecf6fbf65e5f6a1a437b06e5ff9a"
e = 65537

sum = int(sum, 16)
n = int(n, 16)
c = int(c, 16)

phi = n - sum + 1
d = pow(e, -1, phi)
m = pow(c, d, n)

print(long_to_bytes(m))
```

Run the program and receive the flag:  

    picoCTF{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_92fe3557}
