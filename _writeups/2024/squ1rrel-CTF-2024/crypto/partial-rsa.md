---
layout: writeup
category: squ1rrel-CTF-2024
chall_description:
points: 450
solves: 35
tags: crypto rsa coppersmith stereotyped-message-attack
date: 2024-4-28
comments: false
---

Hmm? What's wrong with using the same flag format again? Whisper it in my ear so they don't hear.

[partialrsa.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/squ1rrel-CTF-2024/partialrsa.txt)  

---

Here's partialrsa.txt:  

```
n: 103805634552377307340975059685101156977551733461056876355507089800229924640064014138267791875318149345634740763575673979991819014964446415505372251293888861031929442007781059010889724977253624216086442025183181157463661838779892334251775663309103173737456991687046799675461756638965663330282714035731741912263
e: 3
ct: 24734873977910637709237800614545622279880260333085506891667302143041484966318230317192234785987158021463825782079898979505470029030138730760671563038827274105816021371073990041986605112686349050253522070137824687322227491501626342218176173909258627357031402590581822729585520702978374712113860530427142416062
```

So the flag description gives us a little hint that the challenge is about the reuse of the same flag format. This refers to the "squ1rrel{" prefix that is used for the flag.  

This is yet another standard RSA attack -- specifically, a variant of Coppersmith known as the stereotyped message attack. Essentially, the idea is that we know the plaintext is something of the form "squ1rrel{XX...XX}", where X's represent unknown characters. Coppersmith's attack allows us to decrypt it. I won't explain it myself, for an actual explanation see [here](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/survey_final.pdf).  

Since this is a very standard attack, we can simply search up a script for it [here](https://gsdt.github.io/blog/2018/07/20/stereotyped-message-attack/).  

The last part we need to do is figure out the number of bytes between the curly braces of the flag. We can just brute force this :)  

Here's the sage script:  

```py
from Crypto.Util.number import *

n = 103805634552377307340975059685101156977551733461056876355507089800229924640064014138267791875318149345634740763575673979991819014964446415505372251293888861031929442007781059010889724977253624216086442025183181157463661838779892334251775663309103173737456991687046799675461756638965663330282714035731741912263
e = 3
ct = 24734873977910637709237800614545622279880260333085506891667302143041484966318230317192234785987158021463825782079898979505470029030138730760671563038827274105816021371073990041986605112686349050253522070137824687322227491501626342218176173909258627357031402590581822729585520702978374712113860530427142416062

prfx = b'squ1rrel{'
for i in range(100):
    m = bytes_to_long(prfx + b'\x00'*i + b'}')
    P.<x> = PolynomialRing(Zmod(n), implementation='NTL')

    pol = (m + x)^e - ct
    roots = pol.small_roots(epsilon=1/30)

    print(i, "Potential solutions:")
    for root in roots:
       print(root, long_to_bytes((m+int(root))%n))
```

    squ1rrel{wow_i_was_betrayed_by_my_own_friend}