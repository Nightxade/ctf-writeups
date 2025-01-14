---
layout: writeup
category: ping-CTF-2023
chall_description:
points: 50
solves: 120
tags: crypto crypto/encoding crypto/obfuscation
date: 2023-12-11
comments: false
---

Welcome to the "private-conversation" challenge, where you find yourself in the role of a cryptanalyst facing an intriguing encrypted message.  

### Scenario  
In the midst of your cryptographic investigations, you stumble upon a fragment of a conversation that appears to be encoded in a highly unusual and complex manner. The content of this conversation could potentially hold significant information or secrets.  

Your challenge is to decrypt the message and reveal its content. The fate of uncovering valuable information lies in your decryption skills. Can you decipher the message and unveil the hidden message within?  

[a24d9877549d9bb256616d238838ba2e_1.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/ping-CTF-2023/a24d9877549d9bb256616d238838ba2e_1.zip)  

---

After a while of staring at this challenge, I figured I might as well try converting the capital letters to 1 and the lowercase letters to 0. I had ruled this out from the start due to the fact that there were 4 different characters, but I ended up finally deciding to try it.  

Converting this binary to ASCII results in this obfuscated C program. After formatting, it looks like this:  

```c
#include <stdio.h>
int main() {
    int o_983add0ed98b556d85ef118183b229dc[] = { 112, 105, 110, 103, 123, 119, 104, 121, 95, 115, 111, 95, 115, 101, 114, 105, 111, 117, 115, 95, 88, 68, 125 };
    const int o_1c1a387bd28e94ce019fcdce8bc08e93 = sizeof((o_983add0ed98b556d85ef118183b229dc)) / sizeof((o_983add0ed98b556d85ef118183b229dc[(0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00)]));
    char o_7645f9e4a84a7e9f0748c6000a041980[o_1c1a387bd28e94ce019fcdce8bc08e93];
    for (int o_f8cd493a89f94a8b1e2e211842b4c8ec = (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00); (o_f8cd493a89f94a8b1e2e211842b4c8ec < o_1c1a387bd28e94ce019fcdce8bc08e93) & !!(o_f8cd493a89f94a8b1e2e211842b4c8ec < o_1c1a387bd28e94ce019fcdce8bc08e93); ++o_f8cd493a89f94a8b1e2e211842b4c8ec) {
        o_7645f9e4a84a7e9f0748c6000a041980[o_f8cd493a89f94a8b1e2e211842b4c8ec] = (char)(o_983add0ed98b556d85ef118183b229dc[o_f8cd493a89f94a8b1e2e211842b4c8ec]);
    };
    for (int o_54314e02607d2bca7f2adf644eae54cf = (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00); (o_54314e02607d2bca7f2adf644eae54cf < o_1c1a387bd28e94ce019fcdce8bc08e93) & !!(o_54314e02607d2bca7f2adf644eae54cf < o_1c1a387bd28e94ce019fcdce8bc08e93); ++o_54314e02607d2bca7f2adf644eae54cf) {
        putchar(o_7645f9e4a84a7e9f0748c6000a041980[o_54314e02607d2bca7f2adf644eae54cf]);
    };
    putchar('\n');
    return (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00);
};
```

This is clearly just printing the characters corresponding to the ASCII codes of the array, so a Decimal to ASCII converter will give us our flag!  

    ping{why_so_serious_XD}