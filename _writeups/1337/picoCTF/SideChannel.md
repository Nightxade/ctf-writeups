---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/DxIdXVH.png
points: 400
solves: 1949
tags: forensics side-channel timing
date: 1337-11-27
comments: false
---

There's something fishy about this PIN-code checker, can you figure out the PIN and get the flag?  
Download the PIN checker program here [pin_checker](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/pin_checker)  
Once you've figured out the PIN (and gotten the checker program to accept it), connect to the master server using nc saturn.picoctf.net [port #] and provide it the PIN to get your flag.  

---

We’re given a file, `pin_checker`. `chmod +x pin_checker` to enable execution. `./pin_checker to execute` → it asks for an 8 digit PIN and informs us whether or not it is the correct PIN.  

The name of this challenge is *SideChannel*. This is definitely a reference to side channel attacks, attacks that are facilitated by a program’s leaking of information. Reading Hint 1 or having some knowledge of side channel attacks allows us to understand that this is a *timing-based* side channel attack.  

A timing-based side channel attack essentially analyzes how long a program executes to attack the program. In this case, one thought might be to progressively try different digits in each position and choose the one that takes the longest amount of time.  

Note: It should make sense why we choose the option that takes the longest duration of time. When the program checks the digits of the input, if the first digit is wrong, it should halt execution there. If the first digit is right, it should continue execution and check the second digit, thus running more operations.  

Thus, we can create a simple python program for this:  

1. We’ll set up execution such that it continues until it finds the correct PIN → this is because time is usually somewhat inconsistent, so your first few tries may not return the right PIN.  
2. Initialize the input as 00000000.  
3. Set up a for loop that traverses through all the positions of the PIN.  
    3.1. Create variables for the maximum time taken and a number corresponding to that max time. Initialize max_time to 0 or a small enough number.  
    3.2. Now, we’ll set up a for loop to test all possible digits in that one position.  
    . . 3.2.1. Create the input  
    . . 3.2.2. Execute pin_checker with receiving standard input  
    . . 3.2.3. Start timing  
    . . 3.2.4. Send input to stdin and record output and error.  
    . . 3.2.5. End timing  
    . . 3.2.6. Check if the duration of time is greater than the current maximum duration  
    . . 3.2.7. If yes, change `max_time` and `max_num`.  
    . . 3.2.8. Check if the byte string `Access denied` is in the output.  
    . . 3.2.9. If no, print out the input because this is our desired PIN and set the flag to `True` to break out of the while loop.  

```py
import subprocess
import os
import time

flag = False
while not flag:
        string = "00000000"
        for i in range(8):
                times = []
                max_time = 0
                max_num = 0
                for j in range(10):
                        input  = string[:i] + str(j) + string[i+1:]
                        p = subprocess.Popen('./pin_checker', stdin=subprocess.PIPE, stdout=subprocess.PIPE) #NOTE: no shell=True here
                        start = time.time()
                        output, error = p.communicate(bytes(os.linesep.join([input]), 'ascii'))
                        end = time.time()
                        #print(input, end - start)
                        if end - start > max_time:
                                max_time = end - start
                                max_num = j
                        times.append(end - start)
                        if b"Access denied" not in output:
                                print(input)
                                flag = True
                string = string[:i] +  str(max_num) + string[i+1:]
                #print(times)

        print(string)
```

Once this program finishes execution (it may take a while) the problem is complete. Connect to the server and submit your pin to get the flag!  

    picoCTF{t1m1ng_4tt4ck_914c5ec3}
