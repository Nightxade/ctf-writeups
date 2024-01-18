---
layout: writeup
category: UofT-CTF-2024
chall_description: N/A
points: 100
solves: 730
tags: forensics
date: 2024-1-15
comments: false
---

We swiped a top-secret file from the vaults of a very secret organization, but all the juicy details are craftily concealed. Can you help me uncover them?  

Author: SteakEnthusiast  
[secret.pdf](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UofT-CTF-2024/secret.pdf)  

---

Opening up the file, we see some redacted text in the PDF. Conveniently, though, we can highlight and copy text from the PDF. Simply highlighting the redacted area and doing Ctrl+C and pasting somewhere else gives us the flag!  

    uoftctf{fired_for_leaking_secrets_in_a_pdf}