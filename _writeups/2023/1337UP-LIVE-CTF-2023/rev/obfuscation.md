---
layout: writeup
category: 1337UP-LIVE-CTF-2023
chall_description: https://i.imgur.com/phxzWpd.png
points: 100
solves: 213
tags: 1337UP-LIVE-CTF-2023 rev rev/obfuscation rev/xor
date: 2023-11-27
comments: false
---

I think I made my code harder to read. Can you let me know if that's true?  

[obfuscation.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/1337UP-LIVE-CTF-2023/obfuscation.zip) 

---

This is what we're given:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
int o_a8d9bf17d390687c168fe26f2c3a58b1[]={42, 77, 3, 8, 69, 86, 60, 99, 50, 76, 15, 14, 41, 87, 45, 61, 16, 50, 20, 5, 13, 33, 62, 70, 70, 77, 28, 85, 82, 26, 28, 32, 56, 22, 21, 48, 38, 42, 98, 20, 44, 66, 21, 55, 98, 17, 20, 93, 99, 54, 21, 43, 80, 99, 64, 98, 55, 3, 95, 16, 56, 62, 42, 83, 72, 23, 71, 61, 90, 14, 33, 45, 84, 25, 24, 96, 74, 2, 1, 92, 25, 33, 36, 6, 26, 14, 37, 33, 100, 3, 30, 1, 31, 31, 86, 92, 61, 86, 81, 38};void o_e5c0d3fd217ec5a6cd022874d7ffe0b9(char* o_0d88b09f1a0045467fd9afc4aa07208c,int o_8ce986b6b3a519615b6244d7fb2b62f8){assert(o_8ce986b6b3a519615b6244d7fb2b62f8 == 24);for (int o_b7290d834b61bc1707c4a86bad6bd5be=(0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00);(o_b7290d834b61bc1707c4a86bad6bd5be < o_8ce986b6b3a519615b6244d7fb2b62f8) & !!(o_b7290d834b61bc1707c4a86bad6bd5be < o_8ce986b6b3a519615b6244d7fb2b62f8);++o_b7290d834b61bc1707c4a86bad6bd5be){o_0d88b09f1a0045467fd9afc4aa07208c[o_b7290d834b61bc1707c4a86bad6bd5be] ^= o_a8d9bf17d390687c168fe26f2c3a58b1[o_b7290d834b61bc1707c4a86bad6bd5be % sizeof((o_a8d9bf17d390687c168fe26f2c3a58b1))] ^ (0x000000000000266E + 0x0000000000001537 + 0x0000000000001B37 - 0x00000000000043A5);};};int o_0b97aabd0b9aa9e13aa47794b5f2236f(FILE* o_eb476a115ee8ac0bf24504a3d4580a7d){if ((fseek(o_eb476a115ee8ac0bf24504a3d4580a7d,(0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00),(0x0000000000000004 + 0x0000000000000202 + 0x0000000000000802 - 0x0000000000000A06)) < (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00)) & !!(fseek(o_eb476a115ee8ac0bf24504a3d4580a7d,(0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00),(0x0000000000000004 + 0x0000000000000202 + 0x0000000000000802 - 0x0000000000000A06)) < (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00))){fclose(o_eb476a115ee8ac0bf24504a3d4580a7d);return -(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03);};int o_6a9bff7d60c7b6a5994fcfc414626a59=ftell(o_eb476a115ee8ac0bf24504a3d4580a7d);rewind(o_eb476a115ee8ac0bf24504a3d4580a7d);return o_6a9bff7d60c7b6a5994fcfc414626a59;};int main(int o_f7555198c17cb3ded31a7035484d2431,const char * o_5e042cacd1c140691195c705f92970b7[]){char* o_3477329883c7cec16c17f91f8ad672df;char* o_dff85fa18ec0427292f5c00c89a0a9b4=NULL;FILE* o_fba04eb96883892ddecbb0f397b51bd7;if ((o_f7555198c17cb3ded31a7035484d2431 ^ 0x0000000000000002)){printf("\x4E""o\164 \x65""n\157u\x67""h\040a\x72""g\165m\x65""n\164s\x20""p\162o\x76""i\144e\x64""!");exit(-(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03));};o_fba04eb96883892ddecbb0f397b51bd7 = fopen(o_5e042cacd1c140691195c705f92970b7[(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03)],"\x72""");if (o_fba04eb96883892ddecbb0f397b51bd7 == NULL){perror("\x45""r\162o\x72"" \157p\x65""n\151n\x67"" \146i\x6C""e");return -(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03);};int o_102862e33b75e75f672f441cfa6f7640=o_0b97aabd0b9aa9e13aa47794b5f2236f(o_fba04eb96883892ddecbb0f397b51bd7);o_dff85fa18ec0427292f5c00c89a0a9b4 = (char* )malloc(o_102862e33b75e75f672f441cfa6f7640 + (0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03));if (o_dff85fa18ec0427292f5c00c89a0a9b4 == NULL){perror("\x4D""e\155o\x72""y\040a\x6C""l\157c\x61""t\151o\x6E"" \145r\x72""o\162");fclose(o_fba04eb96883892ddecbb0f397b51bd7);return -(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03);};fgets(o_dff85fa18ec0427292f5c00c89a0a9b4,o_102862e33b75e75f672f441cfa6f7640,o_fba04eb96883892ddecbb0f397b51bd7);fclose(o_fba04eb96883892ddecbb0f397b51bd7);o_e5c0d3fd217ec5a6cd022874d7ffe0b9(o_dff85fa18ec0427292f5c00c89a0a9b4,o_102862e33b75e75f672f441cfa6f7640);o_fba04eb96883892ddecbb0f397b51bd7 = fopen("\x6F""u\164p\x75""t","\x77""b");if (o_fba04eb96883892ddecbb0f397b51bd7 == NULL){perror("\x45""r\162o\x72"" \157p\x65""n\151n\x67"" \146i\x6C""e");return -(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03);};fwrite(o_dff85fa18ec0427292f5c00c89a0a9b4,o_102862e33b75e75f672f441cfa6f7640,sizeof(char),o_fba04eb96883892ddecbb0f397b51bd7);fclose(o_fba04eb96883892ddecbb0f397b51bd7);free(o_dff85fa18ec0427292f5c00c89a0a9b4);return (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00);};
```

Wow, that's a mess to read!  
First things first, I tried looking up a C deobfuscator. No good results... looks like I'll have to do this by hand!  

By replacing variable names using [](http://www.unit-conversion.info/texttools/replace-text/), formatting the code, and replacing most weird ints and strings, I ended up with this:  
*(Note to self -- why not automate this with Python??)*  
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int arr[]={42, 77, 3, 8, 69, 86, 60, 99, 50, 76, 15, 14, 41, 87, 45, 61, 16, 50, 20, 5, 13, 33, 62, 70, 70, 77, 28, 85, 82, 26, 28, 32, 56, 22, 21, 48, 38, 42, 98, 20, 44, 66, 21, 55, 98, 17, 20, 93, 99, 54, 21, 43, 80, 99, 64, 98, 55, 3, 95, 16, 56, 62, 42, 83, 72, 23, 71, 61, 90, 14, 33, 45, 84, 25, 24, 96, 74, 2, 1, 92, 25, 33, 36, 6, 26, 14, 37, 33, 100, 3, 30, 1, 31, 31, 86, 92, 61, 86, 81, 38};
void func1(char* paramstr,int paramint){
    assert(paramint == 24);
    for (int i=0; (i < paramint); ++i) {
        paramstr[i] ^= arr[i % sizeof((arr))] ^ (0x1337);
    };
};

int func2(FILE* fileparam){
    if ((fseek(fileparam,(0x000 + 0x200 + 0x800 - 0xA00),(0x004 + 0x202 + 0x802 - 0xA06)) < (0x000 + 0x200 + 0x800 - 0xA00)) & !!(fseek(fileparam,(0x000 + 0x200 + 0x800 - 0xA00),(0x004 + 0x202 + 0x802 - 0xA06)) < (0x000 + 0x200 + 0x800 - 0xA00))){
        fclose(fileparam);
        return -1;
    };
    int a=ftell(fileparam);
    rewind(fileparam);
    return a;
};

int main(int arg1int,const char * arg2str[]){
    char* str1;
    char* str2=NULL;
    FILE* file;
    if ((arg1int ^ 0x002)){
        printf("Not enough arguments provided!");
        exit(-1);
    };
    file = fopen(arg2str[1],"r");
    if (file == NULL){
        perror("Error opening file: No such file or directory");
        return -1;
    };
    int maybesize=func2(file);
    str2 = (char* )malloc(maybesize + 1);
    if (str2 == NULL){
        perror("Memory allocation error");
        fclose(file);
        return -1;
    };
    fgets(str2,maybesize,file);
    fclose(file);
    func1(str2,maybesize);
    file = fopen("output", "wb");
    if (file == NULL){
        perror("Error opening file");
        return -1;
    };
    fwrite(str2,maybesize,sizeof(char),file);
    fclose(file);
    free(str2);
    return 0;
};
```

This is now readable code! Well, what is it doing?  

Well, most of the function seems to be dealing with errors, so we can pretty much just ignore all of that. The important part lies in func1, which seems to be performing an XOR encryption using the first 24 bytes of key on the first 24 bytes of flag, although note that it seems that the function requires the flag to be 24 bytes anyways.  

We can just write a short python script to decrypt this! (Or, alternatively, you could run this same C program with the output as the input, as that will reverse the XOR encryption).  
```py
key = [42, 77, 3, 8, 69, 86, 60, 99, 50, 76, 15, 14, 41, 87, 45, 61, 16, 50, 20, 5, 13, 33, 62, 70, 70, 77, 28, 85, 82, 26, 28, 32, 56, 22, 21, 48, 38, 42, 98, 20, 44, 66, 21, 55, 98, 17, 20, 93, 99, 54, 21, 43, 80, 99, 64, 98, 55, 3, 95, 16, 56, 62, 42, 83, 72, 23, 71, 61, 90, 14, 33, 45, 84, 25, 24, 96, 74, 2, 1, 92, 25, 33, 36, 6, 26, 14, 37, 33, 100, 3, 30, 1, 31, 31, 86, 92, 61, 86, 81, 38]

f = open('rev/obfuscation/chall/output', 'rb').read()

flag = ''
for i in range(24):
    print(f[i], end=' ')
    flag += chr((f[i] ^ 0x1337 ^ key[i]))
print(flag)
```

But, after running the program, I didn't receive the flag! Instead, I received some weird non-ASCII string...  

I decided that I might as well check the decimal values of each character to ensure that it wasn't some weird quirk of Python going wrong. However, I immediately noticed that these values seemed suspiciously close to each other:  

    [4937, 4942, 4948, 4937, 4935, 4946, 4937, 4948, 4937, 4987, 4954, 4914, 4921, 4982, 4954, 4935, 4976, 4982, 4953, 4967, 4925, 4925, 4989, 4864]

If it was some error in my XOR decryption, why would all the characters be so close together? Moreover, we know that the prefix of the flag is INTIGRITI{. Doesn't 4937 appear in every single place the I appears in...?  

Perhaps this is actually a shifted version of the flag. I calculated the shift based on the I, and shifted each value down by that shift.  
```py
key = [42, 77, 3, 8, 69, 86, 60, 99, 50, 76, 15, 14, 41, 87, 45, 61, 16, 50, 20, 5, 13, 33, 62, 70, 70, 77, 28, 85, 82, 26, 28, 32, 56, 22, 21, 48, 38, 42, 98, 20, 44, 66, 21, 55, 98, 17, 20, 93, 99, 54, 21, 43, 80, 99, 64, 98, 55, 3, 95, 16, 56, 62, 42, 83, 72, 23, 71, 61, 90, 14, 33, 45, 84, 25, 24, 96, 74, 2, 1, 92, 25, 33, 36, 6, 26, 14, 37, 33, 100, 3, 30, 1, 31, 31, 86, 92, 61, 86, 81, 38]

f = open('rev/obfuscation/chall/output', 'rb').read()

flag = ''
for i in range(24):
    print(f[i], end=' ')
    flag += chr((f[i] ^ 0x1337 ^ key[i]) - (4937 - 73))
print(flag)
```
And voila! We get the flag! On a side note it also contains a base64 encoded string that says "goodjob"

    INTIGRITI{Z29vZGpvYg==}