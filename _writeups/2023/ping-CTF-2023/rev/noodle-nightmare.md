---
layout: writeup
category: ping-CTF-2023
chall_description: N/A
points: 50
solves: 206
tags: rev obfuscation
date: 12-11-2023
comments: false
---

In the last programming session, Bajtek unleashed a coding catastrophe – his spaghetti code was so messy that even the compiler threw up its hands in surrender. Colleagues attempted to debug it, but the code was like a Rubik's Cube on a caffeine overdose. Bajtek proudly declared it an avant-garde programming masterpiece, leaving his coworkers wondering if they should call a programmer's version of an exorcist. In the end, they renamed his file "spaghetti.cpp" to "noodleNightmare.cpp" as a memorial to the chaotic session.  

[58df855a70e2573ee69865930774973a.zip](https://github.com/Nightxade/ctf-writeups/assets/CTFs/ping-CTF-2023/58df855a70e2573ee69865930774973a.zip)  

---

Check out `noodleNightmare.cpp`. Seems like we're given a ton of include statements in order. Maybe we can parse this in Python?  

Copying the entire program, I used [this site](http://www.unit-conversion.info/texttools/replace-text/) to add commas and nice formatting to the program to create an array. Then, I used Python to print nicely formatted output of the program. Then, with a little manual tweaking, I got this:  

```cpp
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>

using namespace std  ;
int main() {
    string _ = "Code that overuses }{ GOTO statements ratherzx than_structured programminjg constructqs, resulting in convoluted and unmaintainable programs, is often called spaghetti code. Such code has a complex and tangled control structure, resulting in a program flow that is conceptually like a bowl of spaghetti, twisted and tangled.";  
    cout << "People always say that my code is spaghetti, but I don't see it. Can you help me find the flag?"  << endl  ;
    string ____  ;
    cin >> ____  ;
    string __ = "";  for ( int ______ = 0  ; ______ < 55  ; ++______) {
        __ += "a"; 
    }
    __[ 0 ] = _[ 63 ]  ;
    __[ 1 ] = _[ 71 ]  ;
    __[ 2 ] = _[ 34 ]  ;
    __[ 3 ] = _[ 66 ]  ;
    __[ 4 ] = _[ 20 ]  ;
    __[ 5 ] = _[ 71 ]  ;
    __[ 6 ] = _[ 5 ]  ;
    __[ 7 ] = _[ 51 ]  ;
    __[ 8 ] = _[ 71 ]  ;
    __[ 9 ] = _[ 15 ]  ;
    __[ 10 ] = _[ 51 ]  ;
    __[ 11 ] = _[ 128 ]  ;
    __[ 12 ] = _[ 7 ]  ;
    __[ 13 ] = _[ 2 ]  ;
    __[ 14 ] = _[ 51 ]  ;
    __[ 15 ] = _[ 255 ]  ;
    __[ 16 ] = _[ 6 ]  ;
    __[ 17 ] = _[ 3 ]  ;
    __[ 18 ] = _[ 34 ]  ;
    __[ 19 ] = _[ 51 ]  ;
    __[ 20 ] = _[ 56 ]  ;
    __[ 21 ] = _[ 1 ]  ;
    __[ 22 ] = _[ 2 ]  ;
    __[ 23 ] = _[ 3 ]  ;
    __[ 24 ] = _[ 51 ]  ;
    __[ 25 ] = _[ 71 ]  ;
    __[ 26 ] = _[ 15 ]  ;
    __[ 27 ] = _[ 51 ]  ;
    __[ 28 ] = _[ 3 ]  ;
    __[ 29 ] = _[ 7 ]  ;
    __[ 30 ] = _[ 15 ]  ;
    __[ 31 ] = _[ 71 ]  ;
    __[ 32 ] = _[ 3 ]  ;
    __[ 33 ] = _[ 13 ]  ;
    __[ 34 ] = _[ 51 ]  ;
    __[ 35 ] = _[ 5 ]  ;
    __[ 36 ] = _[ 1 ]  ;
    __[ 37 ] = _[ 51 ]  ;
    __[ 38 ] = _[ 13 ]  ;
    __[ 39 ] = _[ 3 ]  ;
    __[ 40 ] = _[ 7 ]  ;
    __[ 41 ] = _[ 2 ]  ;
    __[ 42 ] = _[ 51 ]  ;
    __[ 43 ] = _[ 71 ]  ;
    __[ 44 ] = _[ 34 ]  ;
    __[ 45 ] = _[ 51 ]  ;
    __[ 46 ] = _[ 7 ]  ;
    __[ 47 ] = _[ 15 ]  ;
    __[ 48 ] = _[ 15 ]  ;
    __[ 49 ] = _[ 3 ]  ;
    __[ 50 ] = _[ 32 ]  ;
    __[ 51 ] = _[ 128 ]  ;
    __[ 52 ] = _[ 93 ]  ;
    __[ 53 ] = _[ 276 ]  ;
    __[ 54 ] = _[ 19 ]  ;
    if ( ____ == __ ) {
        cout << "Congratulations, you have untangled this spaghetti!"  << endl  ;
    }
    else {
        cout << "Not this time!"  << endl  ;
    }
}
```

So it seems like it constructs the flag string, i.e. `__`, from the this initial string `_`. Then, it checks it against user input of `___`. Well, why don't we just add a `cout` statement before the program ends to get the flag?  

```cpp
cout << __ << '\n';
```

Now running the program returns the flag!  

    ping{it_is_bad_when_code_is_easier_to_read_in_assembly}