---
layout: writeup
category: 1337UP-LIVE-CTF-2023
chall_description: https://i.imgur.com/RrFt3ll.png
points: 408
solves: 49
tags: crypto crypto/xor crypto/modular-arithmetic
date: 2023-11-27
comments: false
---

Can you find a and b?  
[notsosmooth.py](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/1337UP-LIVE-CTF-2023/notsosmooth.py)

---

We're given the following:
```py
from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor
from random import randint
from flag import FLAG

def f(x, n):  
    return (pow(u,n,p)*x + v*(1-pow(u,n,p))*pow(1-u, -1, p)) % p  

p = 97201997431130462639713476119411091922677381239967611061717766639853376871260165905989218335681560177626304205941143288128749532327607316527719299945637260643711897738116821179208534292854942631428531228316344113303402450588666012800739695018334321748049518585617428717505851025279186520225325765864212731597
u = 14011530787746260724685809284106528245188320623672333581950055679051366424425259006994945665868546765648275822501035229606171697373122374288934559593175958252416643298136731105775907857798815936190074350794406666922357841091849449562922724459876362600203284195621546769313749721476449207319566681142955460891977927184371401451946649848065952527323468939007868874410618846898618148752279316070498097254384228565132693552949206926391461108714034141321700284318834819732949544823937032615318011463993204345644038210938407875147446570896826729265366024224612406740371824999201173579640264979086368843819069035017648357042
v = 16560637729264127314502582188855146263038095275553321912067588804088156431664370603746929023264744622682435376065011098909463163865218610904571775751705336266271206718700427773757241393847274601309127403955317959981271158685681135990095066557078560050980575698278958401980987514566688310172721963092100285717921465575782434632190913355536291988686994429739581469633462010143996998589435537178075521590880467628369030177392034117774853431604525531066071844562073814187461299329339694285509725214674761990940902460186665127466202741989052293452290042871514149972640901432877318075354158973805495004367245286709191395753
w = 30714296289538837760400431621661767909419746909959905820574067592409316977551664652203146506867115455464665524418603262821119202980897986798059489126166547078057148348119365709992892615014626003313040730934533283339617856938614948620116906770806796378275546490794161777851252745862081462799572448648587153412425374338967601487603800379070501278705056791472269999767679535887678042527423534392867454254712641029797659150392148648565421400107500607994226410206105774620083214215531253544274444448346065590895353139670885420838370607181375842930315910289979440845957719622069769102831263579510660283634808483329218819353
a = randint(0, 2**2048)
b = randint(0, 2**2048)
A = f(w, a)
B = f(w, b)
key = long_to_bytes(f(B, a))[:len(FLAG)]
enc = strxor(FLAG, key)
print(f"{A = }")
print(f"{B = }")
print(f"{enc = }")

"""
A = 7393401480034113709683683682039780458211722756040975666277858366986963864147091724359492764726999692812421940595309756560491142512219957986281425163574890752574157617546760386852366936945888357800966704941013951530688031419816817272581287237223765833452303447283089906937413964658335387593899889933721262202
B = 6919381992041136573008188094979879971060160509085428532054694712745921654244468113796582501225839242977870949915769181804595896718922228206397860738237256125972615830799470450058633231003927061049289907097099916321068776956652172887225970642896455423957706532253349472544176183473470843719479781727784095989
enc = b'\xcfW\x85\x8d\xedU\xdd\xd9`\x16f\xb8j(\xeb9-\x1b\xb8\x18 0av\xe5\xabK\xc6'
"""
```

Hm. Let's break this down step by step.  

	1. We have 3 known variables used in the funciton -- *p*, *u*, *v*
	2. We have 1 known variable that is used for the x parameter of *f(x, n)* to get *A* and *B* -- *w*
	3. We have 2 unknown, random variables in the range [0, 2^2048) that are used for the n parameter of *f(x, n)* to produce *A* and *B* -- *a* and *b*, respectively
	4. We are given *A*, *B*, and the encrypted flag
	5. The key is derived from *f(B, a)*

Now let's try and figure out this function:  

	1. There are two terms
	2. *x* is used for multiplication in the first term
	3. *n* is used for the exponent of *u* with modulus *p*
	4. *pow(u, n, p)* is involved in both terms
	5. *pow(1-u, -1, p)*, i.e. the modular inverse of *1 - u* for modulus *p*, is used in the 2nd term... this seems suspicious
	6. The entire expression is taken mod *p*

After analysis, the *pow(1 - u, -1, p)* seemed the most suspicious to me. Why is the modular inverse of *1 - u* involved in the expression when *1 - u* is used nowhere else?  

I decided that, maybe I should try to get rid of this. It is easy to get rid of this by simply multiplying *f(x, n)* by *1 - u*, as the entire expression is already taken mod *p*. I then simplified and factored in the following process:  

```py
f(x, n) = (pow(u,n,p)*x + v*(1-pow(u,n,p))*pow(1-u, -1, p)) % p
f(x, n) * (1 - u) = (pow(u,n,p)*x*(1-u) + v*(1-pow(u,n,p))*1) % p
f(x, n) * (1 - u) = ( (pow(u,n,p)) * (x - xu - v) + v) ) % p
```

So now, I had related *f(x, n)* to the product of two numbers.  
Because *x* is only ever *B* or *w*, we will always know the value of *x*. Since we know the value of *x*, *u*, and *v*, the only unknown in this equation will always be n. However, I realized that it was not possible to use this to solve directly for *a = n* with the relation *f(w, a) = A*, as it would require brute forcing a very large integer.  

At this point, I decided to turn my attention back to the actual function calls:  

	A = f(w, a)
	B = f(w, b)
	key = f(B, a)

Both *A* and *key* involve the same value of *n*. I thought that was perhaps more useful than using *B*'s function in some way because (1) we already know the value of B, so it shouldn't really make an impact on *f(B, a)* unless it leads to some major insight (which I was hesitant to explore because it felt very bashy) and (2) because we know B, we don't really care about *b*; as far as I could tell, *a* was more important because it was the only unknown of *f(B, a)*.  

Therefore, I rewrote my equations for *A* and *key* with the expression I had proved earlier.  

```py
A = f(w, a) = ( ( (pow(u,a,p)) * (w - wu - v) + v) ) % p ) / (1 - u)
key = f(B, a) = ( ( (pow(u,a,p)) * (B - Bu - v) + v) ) % p ) / (1 - u)
```

Hey... wait a minute. We have two equations, and two unknowns, *a* and *key*. We know we cannot directly compute *a* from these equations; however, *a* is used in the same way in both equations, to calculate *pow(u,a,p)*. Therefore, *pow(u,a,p)* can be essentially considered the unknown instead. So, what if use the first equation, in which we only have one unknown, i.e. *pow(u,a,p)*, to solve for that unknown, and then substitute into the second equation to solve for key?  

Also, remember that division in modular arithmetic is essentially equivalent to multiplying by the modular inverse -- this allows us to compute these values!  

Also x2, you don't even have to directly solve for *pow(u,a,p)*. It's actually possible to go directly from *A* to *key* by using the only difference between the two equations, i.e. *(w - wu - v)* and *(B - Bu - v)*.  

But here was the final math I did to get the solution:  

```py
pow(u,a,p) = ( (A * (1 - u) - v) * pow(w - wu - v, -1, p) ) % p
# Substitute this into the equation for key to get the flag!  
```

Once, we have the key, a simple strxor() to decrypt returns our flag :)  

	INTIGRITI{1e863724be1ea6d3e}

Implementation of the above:  
```py
modinv = pow(1-u, -1, p)
ap = ((A * ((1 - u) % p) - v) * pow(w - w * u - v, -1, p)) % p
k = (ap * B + v * (1 - ap) * (modinv)) % p
k = long_to_bytes(k)[:len(enc)]

def strxor(a, b):
    res = b''
    for i in range(len(a)):
        res += (a[i] ^ b[i]).to_bytes(1, 'big')
    return res

print(strxor(enc, k))
```