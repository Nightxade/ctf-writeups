---
layout: writeup
category: BCA-CTF-2024
chall_description:
points: 150
solves: 46
tags: crypto rsa branch-and-prune
date: 2024-06-12
comments: false
---

My client is a bit picky with the primes they are willing to use...

(Sequel from BCACTF 4.0)

[superstitious-2.py](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/superstitious-2.py)  
[superstitious-2.txt](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/superstitious-2.txt)  

---

Here's the Python source:  

```py
from Crypto.Util.number import *
def myGetPrime():
    while True:
        x = getRandomNBitInteger(1024) & ((1 << 1024) - 1)//3
        if isPrime(x):
            return x
p = myGetPrime()
q = myGetPrime()
n = p * q
e = 65537
message = open('flag.txt', 'rb')
m = bytes_to_long(message.read())
c = pow(m, e, n)
open("superstitious-2.txt", "w").write(f"n = {n}\ne = {e}\nc = {c}")
```

Basically, the only thing different about this compared to standard RSA is that the every other bit of p and q is **guaranteed** to be 0. (Since `((1 << 1024) - 1)//3` only has every other bit set).  

Because of this, we can use a technique known as "branch and prune". If implemented with BFS (Breadth First Search), you essentially just move linearly along the bits, considering every single possibility at that bit and testing if it works. The reason we can check if it works is because the first `x` bits of p and q are the only bits that affect the first `x` bits of n. Therefore, `(p*q)%(1<<(x+1)) == n%(1<<(x+1))`. You can think of this as analogous to how it works in base 10 multiplication. The only digits that affect the units digit of a product is the units digits of the two numbers being multiplied. The only digits that affect the tens digit of a produce is the tens and units digits of the two numbers being multiplied. And so on and so forth.  

Normally, this technique doesn't work because the possibilities grow exponentially. But, because every other bit of p and q is known to be 0, this significantly reduces the possibilities for p and q as the process continues.  

Therefore, we can write a simple BFS implemention to calculate p and q:  

```py
from Crypto.Util.number import *

n = 550201148354755741271315125069984668413716061796183554308291706476140978529375848655819753667593579308959498512392008673328929157581219035186964125404507736120739215348759388064536447663960474781494820693212364523703341226714116205457869455356277737202439784607342540447463472816215050993875701429638490180199815506308698408730404219351173549572700738532419937183041379726568197333982735249868511771330859806268212026233242635600099895587053175025078998220267857284923478523586874031245098448804533507730432495577952519158565255345194711612376226297640371430160273971165373431548882970946865209008499974693758670929
e = 65537
c = 12785320910832143088122342957660384847883123024416376075086619647021969680401296902000223390419402987207599720081750892719692986089224687862496368722454869160470101334513312534671470957897816352186267364039566768347665078311312979099890672319750445450996125821736515659224070277556345919426352317110605563901547710417861311613471239486750428623317970117574821881877688142593093266784366282508041153548993479036139219677970329934829870592931817113498603787339747542136956697591131562660228145606363369396262955676629503331736406313979079546532031753085902491581634604928829965989997727970438591537519511620204387132

# NOTE: BFS to find p,q
'''
queue = [(0, 0, 1), (0, 1, 1), (1, 0, 1), (1, 1, 1)] # p,q,blen
i = 1
while not len(queue) == 0:
    p,q,blen = queue.pop(0)
    if i < blen:
        print(i, len(queue))
        i = blen
    mod = 2**(blen)
    if (p*q)%mod == n%mod:
        if blen > 1000 and p*q == n:
            print(p, q)
            break
        else:
            add = 2**(blen + 1)
            blen += 2
            queue.append((p, q, blen))
            queue.append((p + add, q, blen))
            queue.append((p, q + add, blen))
            queue.append((p + add, q + add, blen))
'''

p = 11466867937506443031079406557463511000236825156042986330491372554263065048494616429572254582549332374593524344514321333368747919034845244563606383834070804967345648840205613712911286600828703809116499141392947298788689558078395325755136448592591616295144118450804581480471547613492025968699740517273286296657
q = 47981816076831973450909530669541706953770597006817333749891020556945477629662108524163405141438024312107792294535273473111389298189846712963818162954497000930546383005418285868804270188594230163069868709422261521819309406460567627868198499351382463630966329988388255592530605189569811432880392671877694493697
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)))
```

    bcactf{l4zy_cHall3nG3_WRITinG_f8b335319e464}