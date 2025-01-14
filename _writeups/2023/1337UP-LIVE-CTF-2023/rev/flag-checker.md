---
layout: writeup
category: 1337UP-LIVE-CTF-2023
chall_description: https://i.imgur.com/aipXq4T.png
points: 100
solves: 130
tags: rev rev/rust rev/brute-force
date: 2023-11-27
comments: false
---

Can you beat this FlagChecker?

[flagchecker](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/1337UP-LIVE-CTF-2023/flagchecker) 
[source.rs](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/1337UP-LIVE-CTF-2023/source.rs) 

---
### *Warning: if you came here for an elegant solution, this is not the writeup to be reading!*  

This is what we're given:  
```rust
use std::io;

fn check_flag(flag: &str) -> bool {
    flag.as_bytes()[18] as i32 * flag.as_bytes()[7] as i32 & flag.as_bytes()[12] as i32 ^ flag.as_bytes()[2] as i32 == 36 &&
    flag.as_bytes()[1] as i32 % flag.as_bytes()[14] as i32 - flag.as_bytes()[21] as i32 % flag.as_bytes()[15] as i32 == -3 &&
    flag.as_bytes()[10] as i32 + flag.as_bytes()[4] as i32 * flag.as_bytes()[11] as i32 - flag.as_bytes()[20] as i32 == 5141 &&
    flag.as_bytes()[19] as i32 + flag.as_bytes()[12] as i32 * flag.as_bytes()[0] as i32 ^ flag.as_bytes()[16] as i32 == 8332 &&
    flag.as_bytes()[9] as i32 ^ flag.as_bytes()[13] as i32 * flag.as_bytes()[8] as i32 & flag.as_bytes()[16] as i32 == 113 &&
    flag.as_bytes()[3] as i32 * flag.as_bytes()[17] as i32 + flag.as_bytes()[5] as i32 + flag.as_bytes()[6] as i32 == 7090 &&
    flag.as_bytes()[21] as i32 * flag.as_bytes()[2] as i32 ^ flag.as_bytes()[3] as i32 ^ flag.as_bytes()[19] as i32 == 10521 &&
    flag.as_bytes()[11] as i32 ^ flag.as_bytes()[20] as i32 * flag.as_bytes()[1] as i32 + flag.as_bytes()[6] as i32 == 6787 &&
    flag.as_bytes()[7] as i32 + flag.as_bytes()[5] as i32 - flag.as_bytes()[18] as i32 & flag.as_bytes()[9] as i32 == 96 &&
    flag.as_bytes()[12] as i32 * flag.as_bytes()[8] as i32 - flag.as_bytes()[10] as i32 + flag.as_bytes()[4] as i32 == 8277 &&
    flag.as_bytes()[16] as i32 ^ flag.as_bytes()[17] as i32 * flag.as_bytes()[13] as i32 + flag.as_bytes()[14] as i32 == 4986 &&
    flag.as_bytes()[0] as i32 * flag.as_bytes()[15] as i32 + flag.as_bytes()[3] as i32 == 7008 &&
    flag.as_bytes()[13] as i32 + flag.as_bytes()[18] as i32 * flag.as_bytes()[2] as i32 & flag.as_bytes()[5] as i32 ^ flag.as_bytes()[10] as i32 == 118 &&
    flag.as_bytes()[0] as i32 % flag.as_bytes()[12] as i32 - flag.as_bytes()[19] as i32 % flag.as_bytes()[7] as i32 == 73 &&
    flag.as_bytes()[14] as i32 + flag.as_bytes()[21] as i32 * flag.as_bytes()[16] as i32 - flag.as_bytes()[8] as i32 == 11228 &&
    flag.as_bytes()[3] as i32 + flag.as_bytes()[17] as i32 * flag.as_bytes()[9] as i32 ^ flag.as_bytes()[11] as i32 == 11686 &&
    flag.as_bytes()[15] as i32 ^ flag.as_bytes()[4] as i32 * flag.as_bytes()[20] as i32 & flag.as_bytes()[1] as i32 == 95 &&
    flag.as_bytes()[6] as i32 * flag.as_bytes()[12] as i32 + flag.as_bytes()[19] as i32 + flag.as_bytes()[2] as i32 == 8490 &&
    flag.as_bytes()[7] as i32 * flag.as_bytes()[5] as i32 ^ flag.as_bytes()[10] as i32 ^ flag.as_bytes()[0] as i32 == 6869 &&
    flag.as_bytes()[21] as i32 ^ flag.as_bytes()[13] as i32 * flag.as_bytes()[15] as i32 + flag.as_bytes()[11] as i32 == 4936 &&
    flag.as_bytes()[16] as i32 + flag.as_bytes()[20] as i32 - flag.as_bytes()[3] as i32 & flag.as_bytes()[9] as i32 == 104 &&
    flag.as_bytes()[18] as i32 * flag.as_bytes()[1] as i32 - flag.as_bytes()[4] as i32 + flag.as_bytes()[14] as i32 == 5440 &&
    flag.as_bytes()[8] as i32 ^ flag.as_bytes()[6] as i32 * flag.as_bytes()[17] as i32 + flag.as_bytes()[12] as i32 == 7104 &&
    flag.as_bytes()[11] as i32 * flag.as_bytes()[2] as i32 + flag.as_bytes()[15] as i32 == 6143
}

fn main() {
    let mut flag = String::new();
    println!("Enter the flag: ");
    io::stdin().read_line(&mut flag).expect("Failed to read line");
    let flag = flag.trim();

    if check_flag(flag) {
        println!("Correct flag");
    } else {
        println!("Wrong flag");
    }
}
```

So this flag checker program seems to check all 22 characters of the flag through a series of equations. Well, 11 characters of the flag are already known from the prefix "INTIGRITI{" and the suffix "}". So this is very easily brute forceable by hand if you brute force byte by byte.  

There are only a couple things to keep in mind when you do brute force:

*   Binary &'s are irreversible. This makes equations with & complicated, so try to avoid them! If you do have to brute force them, keep in mind that the value you find might not actually be correct, as binary &'s can result in multiple different values working for a single equation.

*   Operator precedence! See https://www.programiz.com/python-programming/precedence-associativity. Some key things to note are that XOR (^) and AND (&) are always lower precedence than the usual +,-,*,/ operators.

*   Always look for equations in which we know all variables except one! Keep in mind we know flag[0-9] and flag[21], which helps us start out on our brute force journey.  

And that's it! A simple reformatting of the program and brute force should work!  

Reformatting: (this just makes it less painful to use it more easily in python)
```py
f = open('rev/flagchecker/source.rs', 'r').read()
f = f.split(' ')
w = open('rev/flagchecker/reformatted.rs', 'w')

for i in range(len(f)):
    if f[i][:15] == 'flag.as_bytes()':
        f[i] = "flag" + f[i][15:]
        f[i + 1] = ''
        f[i + 2] = ''
    elif f[i][:2] == '&&':
        f[i] = ')\nprint('
    elif f[i] == '==':
        f[i] = ''
        f[i + 1] = f', "should be {f[i + 1]}"'
    w.write(f[i] + ' ' if f[i] != '' else '')
```

Brute force: (the actual brute forcing part)
```py
m = 'INTIGRITI{aaaaaaaaaaa}'
flag = []
for c in m:
    flag.append(ord(c))

print(flag)

flag[15] -= 2
flag[11] = (6143 - flag[15]) // flag[2]
flag[20] -= 10
flag[17] = (((11686 ^ flag[11]) - flag[3]) // flag[9])
flag[10] = 6869 ^ (flag[7] * flag[5]) ^ flag[0]
flag[12] = 7104 - (flag[8] ^ flag[6] * flag[17]) + 16
flag[18] -= 27
flag[19] = 10521 ^ (flag[21] * flag[2] ^ flag[3])
flag[14] = 5440 - (flag[18] * flag[1] - flag[4])
flag[13] = (((4936 ^ flag[21]) - flag[11]) // flag[15])
flag[16] = 8332 ^ (flag[19] + flag[12] * flag[0])

print( flag[18] * flag[7] & flag[12] ^ flag[2] , "should be 36" )
print( flag[1] % flag[14] - flag[21] % flag[15] , "should be -3" )
print( flag[10] + flag[4] * flag[11] - flag[20] , "should be 5141" )
print( flag[19] + flag[12] * flag[0] ^ flag[16] , "should be 8332" )
print( flag[9] ^ flag[13] * flag[8] & flag[16] , "should be 113" )
print( flag[3] * flag[17] + flag[5] + flag[6] , "should be 7090" )
print( flag[21] * flag[2] ^ flag[3] ^ flag[19] , "should be 10521" )
print( flag[11] ^ flag[20] * flag[1] + flag[6] , "should be 6787" )
print( flag[7] + flag[5] - flag[18] & flag[9] , "should be 96" )
print( flag[12] * flag[8] - flag[10] + flag[4] , "should be 8277" )
print( flag[16] ^ flag[17] * flag[13] + flag[14] , "should be 4986" )
print( flag[0] * flag[15] + flag[3] , "should be 7008" )
print( flag[13] + flag[18] * flag[2] & flag[5] ^ flag[10] , "should be 118" )
print( flag[0] % flag[12] - flag[19] % flag[7] , "should be 73" )
print( flag[14] + flag[21] * flag[16] - flag[8] , "should be 11228" )
print( flag[3] + flag[17] * flag[9] ^ flag[11] , "should be 11686" )
print( flag[15] ^ flag[4] * flag[20] & flag[1] , "should be 95" )
print( flag[6] * flag[12] + flag[19] + flag[2] , "should be 8490" )
print( flag[7] * flag[5] ^ flag[10] ^ flag[0] , "should be 6869" )
print( flag[21] ^ flag[13] * flag[15] + flag[11] , "should be 4936" )
print( flag[16] + flag[20] - flag[3] & flag[9] , "should be 104" )
print( flag[18] * flag[1] - flag[4] + flag[14] , "should be 5440" )
print( flag[8] ^ flag[6] * flag[17] + flag[12] , "should be 7104" )
print( flag[11] * flag[2] + flag[15] , "should be 6143" )

m = ''
for i in flag:
    m += chr(i)

print(m)
```

Got the flag :)  

    INTIGRITI{tHr33_Z_FTW}