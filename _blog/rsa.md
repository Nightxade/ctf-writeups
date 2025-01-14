# The Math Behind RSA

First, primes $$p$$ and $$q$$ are selected at random. These need to be rather large, and are typically 128, 256, or 512 bits. These primes are kept secret.  

Then, $$N=pq$$ is calculated. This is our modulus, and is publicly known. Because of how large $$p$$ and $$q$$ are, this should be infeasible to calculate on classical computers (quantum computers are a whole different story, but they're not quite there yet). We also calculate $$\phi (N)=(p-1)(q-1)$$. This is Euler's totient. This is kept private, and, importantly can only be calculated by those who know the factorization of $$N$$.  

We can choose a public exponent value, $$e$$, at this point. It is most commonly 65537. Importantly, e must be coprime to $$\phi (N)$$, because it is used to calculate the private exponent value, $$d$$.  

Essentially, it must hold true that $$ed \equiv 1\;(mod\; \phi (N))$$. In other words, $$d$$ is the *multiplicative inverse* of $$e$$ over the modulus $$\phi (N)$$.  We can find $$d$$ via the Extended Euclidean Algorithm.  

# TODO: Extended Euclidean explanation

Then, encryption and decryption occur as follows, respectively:  

$$m^e \equiv c\; (mod\; N)$$  
Where c is the ciphertext.  
$$c^d \equiv m\; (mod\; N)$$  

Here's a quick explanation on why decryption works:  

$$c^d \equiv m^{ed}\;(mod\;N)$$  
Note that $$ed = k\phi (N) + 1$$ because $$ed \equiv 1\;(mod\; \phi (N))$$  
Therefore,  
$$m^{ed}\;(mod\;N) \equiv m^{k\phi (N) + 1}\;(mod\;N)$$  

According to Euler's Theorem,  
$$m^{k\phi (N)} \equiv 1\;(mod\;N)$$  

Thus,  
$$m^{k\phi (N) + 1} \equiv m^{k\phi (N)} \cdot m \equiv m\;(mod\;N)$$  