---
layout: writeup
category: Iris-CTF-2024
chall_description:
points: 50
solves: 282
tags: rev go
date: 2024-1-7
comments: false
---

Rune? Like the ancient alphabet?  
[whats-a-rune.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/whats-a-rune.tar.gz)  

---

We're given two files, `the` and `main.go`. `the` is filled with some odd text. Here is `main.go`:  

```go
package main

import (
	"fmt"
	"os"
	"strings"
)

var flag = "irisctf{this_is_not_the_real_flag}"

func init() {
	runed := []string{}
	z := rune(0)

	for _, v := range flag {
		runed = append(runed, string(v+z))
		z = v
	}

	flag = strings.Join(runed, "")
}

func main() {
	file, err := os.OpenFile("the", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()
	if _, err := file.Write([]byte(flag)); err != nil {
		fmt.Println(err)
		return
	}
}
```

Given the simplicity of this program, it can actually be quite easily understood without any experience with Golang (i.e. me). Some simple searching and analysis allowed me to understand the program. Here's my commented version:  

```go
package main

import (
	"fmt"
	"os"
	"strings"
)

var flag = "irisctf{this_is_not_the_real_flag}"

func init() {
	runed := []string{} // empty string array
	z := rune(0) // rune = int32 --> casts 0 to an int32.

	for _, v := range flag { // index, element
		runed = append(runed, string(v+z)) // append string(v + z) to runed
		z = v // set z to the current element
	}

	flag = strings.Join(runed, "") // equivalent to Python "".join for an array
} // each element of the encrypted flag is determined by two consecutive elements of the flag

func main() {
	file, err := os.OpenFile("the", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()
	if _, err := file.Write([]byte(flag)); err != nil {
		fmt.Println(err)
		return
	}
} // open "the" and write encrypted flag to it
```

Essentially, this is a very simple encryption that adds two consecutive characters to create each element of the ciphertext. Here's the decryption:  

```py
f = open('the', 'r').read()
print(f)

flag = 'i'
for i in range(1, len(f)):
    flag += chr(ord(f[i]) - ord(flag[i - 1]))

print(flag)
```

Sidenote: be careful -- don't open the file with `rb`, as it won't read the text properly, and result in a failed decryption. Use `r` and the chr() function provided by Python.  

Run the Python file and get the flag!  

    irisctf{i_r3411y_1ik3_num63r5}