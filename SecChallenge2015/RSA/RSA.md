RSA Challenges
==============

> Writeup for Crysys SecChallenge 2015. The original challenges are available
on avatao.com.

## RSA in a nutshell
To have a little more chance in solving the RSA series challenges we should have a rough understanding of how this cryptosystem works.

RSA is a public-key encryption system, thus the two parties (Alice and Bob) have to generate their public and private keys. These key must be constructed in a way that the knowledge of the public key doesn't implies any hints about the private key. RSA achives this by building on the prime factorization which is believed to be computationally difficult.

### Key construction
Choose two big _prime_ number: *p* and *q*

Let `n = p * q`

and `phi(n) = (p - 1) * (q - 1)`  [phi(n) is the *Euler's totient function*]

Choice *d* such that:
 - `d < phi(n)`
 - `gcd(d, phi(n)) = 1`    [d and phi(n) are relative primes]

The compute e = d^-1 mod phi(n), so *e* becomes *d*'s multiplicative inverse with respect to modulo n.

### Naming conventions
|  Variable  |       Name       |
|:----------:|:----------------:|
|      n     |   public modulo  |
|      d     | private exponent |
|      e     |  public exponent |
| Priv(n, d) |    private key   |
|  Pub(n, e) |    public key    |

### En/decryption method
Assume Bob would like to send his *m* message to Alice:
 1. Bob gets Alice's `Pub(n, e)` public key
 2. Bob compute `c = m^e mod n`, and sends it to Alice
 3. Alice receive *c* and get her `Priv(n, d)` private key
 4. Alice compute `m = c^d mod n`, so she has Bob's *m* message

## 1. Getting the public key (75 points)
### Method I
This challenge is a little unusal RSA exercise: encrypt a message. Normally we have the "full" public key (*n* and *e*) and thus encryption is trivial, but now only the public exponent is known (e = 17). The only thing about *n* is that it is 1024 bit long. The "decryption" feature is the only hint we have, so the script gives us `m = c^d mod n`, where *c* is the input number we control.

Let's choose *c1* and *c2* relative prime numbers as input number, and we'll get *m1* and *m2* modulos. Basically the modulo operation could be rearrange into `c1^d = k1 * n + m1` and `c2^d = k2 * n + m2`. Now consider *c12*, where c12 = c1 * c2: `c12^d = (c1*c2)^d = c1^d * c2^d` and  `k3 * n + m3 = (k1 * n + m1) * (k2 * n + m2) = n^2*k1*k2 + n*(k2*m1+k1*m2) + m1*m2` This implies the fact, that: `m1 * m2 = l3 * n + m3`, so (m1*m2-m3) is divisable by n.

If we repeat this with an other *c3* relative prime to *c1* and *c2*, and compute c13 and c23 in the same way, we'll end up having three (almost certainly) different sums with (almost certainly) greatest common divisor of n: c1*c2-c12, c1*c3-c13, c2*c3-c23. (If the gcd doesn't seems to be the _original_ n, than put in another *c4* relative prime to the previous *ci*s.) So simply computing gcd(m1*m2-m12, m1*m3-m13, m2*m3-m23) gives us n, thus encryption is feasable!

```python
from math import gcd

c1 = 2
c2 = 3
c3 = 5

# ...

n = gcd(gcd(m1*m2-m12, m1*m3-m13), m2*m3-m23)
```

### Method II
This method requires less numbers to test, so considered more efficient, but still not certain. Just like at __Method I__ choose two relative prime numbers (*c1* and *c2*) as input number. Denote the decrypted numbers in the response *m1* and *m2*. Now *m1* is computed this way: `m1 = c1^d mod n`. But according to the RSA properties `c1 = m1^e mod n` still holds, where e=17. Rewriting the modulo operation we get: `m1^17 = k1 * n + c1`. So it's clear that `m1^17-c1` is divisible by *n*. Thus compute the gcd of some pairwise relative prime *ci* numbers we should get *n*. (Again, it's still possible to receive one of the divisors of *n* because of the relation of the random *n* and the selected *ci* constaints - this case just restart the script or input more *ci* values!)

## Decrypting a message (150 points)
Now we have to decrypt the given number, but the script will generously decrypt anything which is not the favourite number (that would be cheating...). We still don't know the *n* public modulo, so according to the previous task let's find it out! (Note, that we only have 10 input chance, but finding *n* usually takes 5-6 inputs, so at least 2 input slot still remains!) So we can assume that the *n* is given.

Let's assume the favourite number (which is a random 1024 bit integer) is not prime (if it is a prime or it's smallest prime divisor is very large, simply restart the script :) - the chance of this happening is very low). Find c1 prime number, so that c is divisible by c1. Then consider the following: `m = c^d mod n = (c1*c2)^d mod n` but `(c1*c2)^d mod n = ((c1^d mod n) * (c2^d mod n)) mod n = (m1 * m2) mod n` where n, m1, and m2 are given, thus m is given as well.

```sage
fav = [favourite number]
for i in primes_first_n(50000):
    if fav % i == 0:
        print "prime divisor = ", i
        break
c1 = [smallest prime divisor]
c2 = fav / [smallest prime divisor]
```

## Decrypting a message with no help (250 points)
This time we are able to get the *n* as well, but there's no more decryption... Running multiple times the script we can get multiple `m^17 mod n_i = c_i` pairs. These equations are exactly like the Chinese Remainder Theorem requires, so collect some (n_i, c_i) pairs (17 pieces of pairs would be sufficient, because in the end calculation of Chinese Remainder Theorem the modulo would be prod(n_i, i:=1..17) and because of m < n_i, m^17 < prod(n_i, i:=1..17) so that there's no need to apply the modulo operation). Then we'll get c = m^17, thus simply computing the 17th root of *c* *m* could be calculated!

```python
def extended_gcd(a, b):
    x,y = 0, 1
    lastx, lasty = 1, 0

    while b:
        a, (q, b) = b, divmod(a,b)
        x, lastx = lastx-q*x, x
        y, lasty = lasty-q*y, y

    return (lastx, lasty, a)

def chinese_remainder_theorem(items):
  N = 1
  for n, a in items:
    N *= n

  result = 0
  for n, a in items:
    m = N/n
    r, s, d = extended_gcd(n, m)
    if d != 1:
      raise "Input not pairwise co-prime"
    result += a*s*m

  return result % N, N

nums = [ 17 items of (n_i, c_i) tuples ]

c, _ = chinese_remainder_theorem(nums)

# c is m^17, so take its 17th root
# and binascii.unhexlify the given value
# so you get the flag
```

[This type of attack is named Håstad's Broadcast Attack - as the flag explains]