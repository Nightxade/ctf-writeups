---
layout: writeup
category: Vishwa-CTF-2024
chall_description:
points: 606
solves: 39
tags: Vishwa-CTF-2024 crypto crypto/brute-force
date: 2024-3-3
comments: false
---

Once again, Mr. David made a blunder by encrypting some confidential data and deleting the original file. Can you help him retrieve the data from the encrypted file?  

Author : Saksham Saipatwar  

[Encrypt.cpp](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Vishwa-CTF-2024/Encrypt.cpp)  
[Encrypted.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Vishwa-CTF-2024/Encrypted.txt)  

---

We're provided a C++ source file and an output. Here's the source:  

```cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
using namespace std;

int createTopping(int curr, int idx, int &not_remainder)
{
    int temp = 0;
    int num = 1;
    num = num << 1;
    while (curr)
    {
        int remainder = curr % idx;
        if (remainder)
        {
            temp = temp * 10 + remainder;
            curr = curr - remainder;
        }
        else
        {
            num = num | 1;
            curr = curr / idx;
        }
        num = num << 1;
    }
    temp = temp << 1;
    temp = temp | 1;
    not_remainder = temp;
    return num | 1;
}

int createBase(int not_remainder)
{
    int num = 0;
    for (int i = 0; i < 30; ++i)
    {
        if (not_remainder)
        {
            num = num | (not_remainder & 1);
            not_remainder = not_remainder >> 1;
        }
        num = num << 1;
    }
    return num;
}

int create(int curr, int idx)
{
    int not_remainder = 0;
    int topping = createTopping(curr, idx, not_remainder);
    int base = createBase(not_remainder);
    int num = base | topping;
    return num;
}

bool checkValidity(int num)
{
    for (int i = 2; i * i < num; ++i)
    {
        if (num % i == 0)
            return false;
    }
    return true;
}

void extraSecurity(vector<int> &encryption)
{
    int n = encryption.size();
    for (int i = 0; i < n; ++i)
    {
        int idx = i + 2;
        if (checkValidity(idx))
        {
            encryption[i] = ~encryption[i];
        }
    }
}

void encode(vector<int> &encryption, const string &data, string &key)
{
    int len = data.length();
    for (int i = 0; i < len; ++i)
    {
        int curr = data[i];
        int idx = (i % 8) + 2;
        int num = create(curr, idx);
        encryption.push_back(num);
    }
}

void applyKey(vector<int> &encryption, string &key)
{
    int n = key.size();
    for (int i = 0; i < n; ++i)
    {
        int curr = key[i];
        int cnt = 0;
        int cpy = curr;
        while (cpy)
        {
            if (cpy & 1)
                ++cnt;
            cpy = cpy >> 1;
        }
        curr = curr << (i + 10);
        while (cnt--)
        {
            curr = curr << 1;
            curr = curr ^ 1;
        }
        int k = encryption.size();
        for (int j = 0; j < k; ++j)
        {
            encryption[j] = encryption[j] ^ curr;
        }
    }
}

void writeToFile(const vector<int> &encryption)
{
    ofstream outfile("Encrypted.txt");
    string data;
    for (auto ele : encryption)
    {
        data += to_string(ele);
        data += " ";
    }
    outfile << data;
    outfile.close();
}

int main()
{
    fstream file;
    file.open("Flag.txt");
    string data;
    file >> data;
    file.close();
    vector<int> encryption;
    string key = "VishwaCTF";
    encode(encryption, data, key);
    applyKey(encryption, key);
    extraSecurity(encryption);
    writeToFile(encryption);
    return 0;
}
```

Skimming the source file, I quickly realized one crucial thing about this encryption -- each byte is encrypted individually. This is of course unlike secure cryptosystems like AES which associate bytes with each other so significantly it is practically impossible to brute force.  

Realizing I can brute force this, I tried creating a dummy file "Flag.txt" that contained a list of all possible characters, i.e. "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-", as well as changing the output file so as not to overwrite the provided "Encrypted.txt" file. However, taking some of the outputs in the "Encrypted.txt" file and doing Ctrl+F for them in my new output file, "Dict.txt", I realized it didn't work. Why not?  

Looking through the source file again, I realized the `createTopping()` function used an `idx` value, which was influenced by the index of the byte in the plaintext. Hence, I realized I only need to modify my brute force slightly, by instead brute forcing every possible byte in every position. For each position, I would create a map that maps the outputted ciphertext byte to the corresponding plaintext byte, and then use that map to figure out the correct plaintext byte for the ciphertext byte at that position in "Encyprted.txt". To do this, I also modified the source file to output to stdout and automated the process via a Python file.  

Here's the modified main function of the source file:  

```cpp
int main()
{
    fstream file;
    file.open("Flag.txt");
    string data;
    file >> data;
    file.close();
    vector<int> encryption;
    string key = "VishwaCTF";
    encode(encryption, data, key);
    applyKey(encryption, key);
    extraSecurity(encryption);
    for(int i = 0; i < encryption.size(); i++) {
        cout << encryption[i] << " ";
    }
    return 0;
}
```

And here's the Python solve script:  

```py
import os

enc = open('Encrypted.txt', 'r').read().split(' ')[:-1]
n = len(enc)

cset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-'
for i in range(n):
    m = dict()
    for c in cset:
        w = open('Flag.txt', 'w')
        w.write('-'*i + c)
        w.close()

        output = os.popen("./Encrypt_mod").read().split(' ')
        # print(c, output)
       
        m[output[-2]] = c
    
    if enc[i] in m.keys():
        print(m[enc[i]], end='')
    else:
        print("Error")
```

Run the script to get the flag!  

    VishwaCTF{BIT5_3NCRYPT3D_D3CRYPTED_M1ND5_D33PLY_TE5T3D}