---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 50
solves: 66
tags: Wolv-CTF-2024 rev rev/brute-force rev/byte-by-byte
date: 2024-3-19
comments: false
---

We encoded a flag, and to make sure that pesky interlopers couldn't reverse it, we shredded the encoding code.

Note: The encoder was written in C. The code is written with good style, but all indents have been removed.

[shredded.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/shredded.py)  
[output.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/output.txt)  
[out.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Wolv-CTF-2024/beginner/out.zip)  

---

I don't really want to write a full writeup for this...  

The basic process is:  

1. Brute force reversing the shredded files into the original C file by just going byte-by-byte. Basically just requires you to format well to be able to get through this quickly. Here's how I did it:  

```py
longest = 39
num_lines = 33

l = ["" for _ in range(longest)]

for i in range(num_lines):
    f = open(f'shredFiles/shred{i}.txt', 'r').read().split('\n')
    for j in range(longest):
        l[j] += f[j]

decrypt = dict()
decrypt[2] = 0
decrypt[4] = 1
decrypt[l[2].index('t')] = 2
decrypt[l[0].index('c')] = 3
decrypt[l[0].index('l')] = 4
decrypt[l[0].index('u')] = 5
decrypt[l[0].index('d')] = 6
decrypt[l[0].index('e')] = 7
decrypt[l[2].index('(')] = 8
decrypt[l[0].index('<')] = 9
decrypt[l[0].index('s')] = 10
decrypt[l[0].index('t')] = 11
decrypt[25] = 12
decrypt[9] = 13
decrypt[l[0].index('o')] = 14
decrypt[l[0].index('.')] = 15
decrypt[l[0].index('h')] = 16
decrypt[l[0].index('>')] = 17
decrypt[l[1].index('>')] = 18
decrypt[l[3].index('C')] = 19
decrypt[l[3].index('T')] = 20
decrypt[l[3].index('E')] = 21
decrypt[l[3].index('D')] = 22
decrypt[l[16].index('*')] = 23
decrypt[l[16].index('1')] = 24
decrypt[7] = 25
decrypt[l[34].index('[')] = 26
decrypt[l[16].index('%')] = 27
decrypt[l[34].index(']')] = 28
decrypt[l[30].index('5')] = 29
decrypt[l[30].index('0')] = 30
decrypt[l[16].index(';')] = 31
decrypt[l[30].index(';')] = 32

# encrypted
print(' '*3, end='')
for i in range(num_lines):
    print(i%10, end='')
print()
for i in range(len(l)):
    print("{:02d}".format(i), "".join(l[i]))

print(decrypt)
print('---------------------------')

# decryption
l2 = [[] for _ in range(longest)]
for i in range(longest):
    for j in range(num_lines):
        l2[i].append(" ")

for i in range(len(l)):
    for j in range(len(l[i])):
        if j in decrypt.keys():
            l2[i][decrypt[j]] = l[i][j]

# decrypted
print(' '*3, end='')
for i in range(num_lines):
    print(i%10, end='')
print()
for i in range(len(l2)):
    print("{:02d}".format(i), "".join(l2[i]))

# with indents
print()
numtabs = 0
for i in range(len(l2)):
    if '}' in l2[i]:
        numtabs -= 1
    print("    "*numtabs + "".join(l2[i]), sep='')
    if '{' in l2[i]:
        numtabs += 1
```

This results in this output:  

```c
#include <stdio.h>               
#include <string.h>              
int main() {                     
    char flag[] = "REDACTED";        
    char inter[51];                  
    int len = strlen(flag);          
    for(int i = 0; i < len; i++) {   
        inter[i] = flag[i];              
    }                                
    for(int i = len; i < 50; i++) {  
        inter[i] = inter[(i*2)%len];     
    }                                
    inter[50] = '\0';                
    char a;                          
    for(int i = 0; i < 50; i++) {    
        a = inter[i];                    
        inter[i] = inter[((i+7)*15)%50]; 
        inter[((i+7)*15)%50] = a;        
    }                                
    for(int i = 0; i < 50; i++) {    
        a = inter[i];                    
        inter[i] = inter[((i+3)*7)%50];  
        inter[((i+3)*7)%50] = a;         
    }                                
    for (int i = 0; i < 50; i++) {   
        inter[i] = inter[i] ^ 0x20;      
        inter[i] = inter[i] ^ 0x5;       
    }                                
    for(int i = 0; i < 50; i++) {    
        a = inter[i];                    
        inter[i] = inter[((i+83)*12)%50];
        inter[((i+83)*12)%50] = a;       
    }                                
    for (int i = 0; i < 50; i++) {   
            printf("\\x%X ", inter[i]);  
    }                                
    return 0;                        
}             
```

2. Do a standard rev on the original C file that encrypts the flag, remembering to loop the opposite way of the original file if it involves swapping bytes. Also, note that the second for loop, which extends the length of the plaintext to 50 bytes, is irrelevant.  

```py
enc_f = open('output.txt', 'rb').read().replace(b'\xff\xfe', b'').replace(b'\x00', b'').decode('ascii').replace('\\x','').split(' ')[:-1]
inter = []

for i in enc_f:
    inter .append(int(i, 16))
    
for i in range(len(inter) - 1, -1, -1):
    a = inter[i]
    inter[i] = inter[((i+83)*12)%50]
    inter[((i+83)*12)%50] = a

for i in range(len(inter)):
    inter[i] ^= 0x20 ^ 0x5

for i in range(len(inter) - 1, -1, -1):
    a = inter[i]
    inter[i] = inter[((i+3)*7)%50]
    inter[((i+3)*7)%50] = a

for i in range(len(inter) - 1, -1, -1):
    a = inter[i]
    inter[i] = inter[((i+7)*15)%50]
    inter[((i+7)*15)%50] = a

for i in range(len(inter)):
    print(chr(inter[i]), end='')
```

Terribly painful challenge, but you get the flag in the end:  

    wctf{sHr3DDinG_L1k3_H3NDr1x_93284}