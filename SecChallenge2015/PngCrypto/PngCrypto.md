PngCrypto Challenges
====================

> Writeup for Crysys SecChallenge 2015. The original challenges are available
on avatao.com.

## PNG in a nutshell
These challenges are all about some PNG images, so let's have a rought understanding of this format. (A very good documentation is available at w3.org/TR/PNG/ but wikipedia also has a great excerpt)

 - PNG files magic header is: `89 50 4e 47 0d 0a 1a 0a`. 
 - PNG files consist of chunks:
     + 4 bytes length
     + 4 bytes chunk type (e.g. IHDR)
     + ... the data
     + 4 bytes CRC
 - first chunk is the "IHDR"
     + 4 bytes [width]
     + 4 bytes [height]
     + 1 bytye [bit depth]
     + 1 byte  [colour type]
     + 1 byte  [compression mode]
     + 1 byte  [filter method]
     + 1 byte  [interlace method]
 - last chunk is the "IEND"
     + empty data part

So assuming the png files are valid (e.g. they have the correct magic header, first block is IHDR and last block is IEND) some bytes are unveiled:

__First 16 bytes:__
```
8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
```

__Last 10 bytes:__
```
0000 0000 4945 4e44 ae42 6082    ....IEND.B`.
```

## Level0 (50 points)
The PNG file is xor-ed with the output of a Linear Congruent Generator. LCG is basically a 1st order function with an additional modulo M operation (thus the range of *y* is bounded): `y = a * x + c (mod M) = (0x4321 * x + 0xbeef) & 0xffff` (subsituted with the constaints of this particular challenge). The initial input *x* is the key, and the next input becomes the current output. In other words: if one state is known, all of the states are known.

In the 'pngcrypto_0.png.enc' we have:
```
00000000: cae0 dc47 cc0d ca4b bfaa 8eb3 7431 8804  ...G...K....t1..
```

So simply xor-ing this with the expected first 16 bytes on 2 bytes groupes:
```python
header = binascii.unhexlify("8950 4e47 0d0a 1a0a 0000 000d 4948 4452".replace(" ", ""))
# the length of 'H' is platform depended, so be careful!
header = struct.unpack("<8H", header)
data = binascii.unhexlify("cae0 dc47 cc0d ca4b bfaa 8eb3 7431 8804".replace(" ", ""))
data = struct.unpack("<8H", data)

[a ^ b for a, b in zip(header, data)]
# [45123, 146, 1985, 16848, 43711, 48782, 31037, 22220]
```

The implemented LCG return the current input first, so basically 45123 is the key. Invoking `python pngcrypto_0.py pngcrypto_0.png.enc out_0.png 45123` indeed gives a valid PNG file, and the flag can be read form the image.

Note, that 'int_to_bytes' function works in little-endian mode (the least significant byte is the first).

## Level1 (50 points)

Essentially is the same as Level0:
```python
header = binascii.unhexlify("8950 4e47 0d0a 1a0a 0000 000d 4948 4452".replace(" ", ""))
header = struct.unpack("<2Q", header)
data = binascii.unhexlify("4caa 9513 ec5d 376c e457 95fc 009d 895d".replace(" ", ""))
data = struct.unpack("<2Q", data)

[a ^ b for a, b in zip(header, data)]
# [7362637591123589829, 1138800794357028836]
```

So the key is 7362637591123589829, again run the script with the proper key gives a valid png file with the flag.

## Level2 (150 points)

Things getting complicated: now *a* and *c* parametes are unknown. The lcg still return the first *x* value, so  *keyx* = 19584286366  can be computed from the first elements xor value. Now the input is grouped into 5 bytes wide words.

```python
header = binascii.unhexlify("8950 4e47 0d0a 1a0a 0000 000d 4948 4452".replace(" ", ""))
# int.from_bytes requires python 3
header = [int.from_bytes(header[5*i:5*(i+1)], byteorder='little') for i in range(0, len(header)//5)]
data = binascii.unhexlify("172e 1ec8 0997 ec7b 40f8 1027 1757 8135".replace(" ", ""))
data = [int.from_bytes(data[5*i:5*(i+1)], byteorder='little') for i in range(0, len(data)//5)]

[a ^ b for a, b in zip(header, data)]
# [19584286366, 1066233099933, 846634822160]
```

We know three consecutive *x* values, so set up the equations based on lcg generator formulas, and do some math :)
```
  (1)    x2 = x1 * a + c (mod M)
  (2)    x3 = x2 * a + c (mod M)
# substract (2) from (1)
(1)-(2)  x2-x3 = (x1-x2) * a (mod M)

# with numbers:
219598277773 = -1046648813567 * a (mod 2^40) = 52862814209 * a (mod 2^40)

# now find the modulo multiplicative inverse of 52862814209 (mod 2^40)
# (using Extended GCD explicitly would be nicer...)
316189496901 = pow(52862814209, 2**40-1, 2**40) = 52862814209^-1 (mod 2^40)

# thus multiply with 316189496901 the equation:
219598277773 * 316189496901 = 23343588493 = a (mod 2^40)

a = 23343588493
c = x2 - x1 * a = 19962495383

```

Or do the hard work with Sage...
```sage
x1 = 19584286366
x2 = 1066233099933
x3 = 846634822160
var('a, c')
M = 2**40

solve_mod([a * x1 + c == x2, a * x2 + c == x3], M)
# [(23343588493, 19962495383)]
```

Here we have *keya* = 23343588493 and *keyc* = 19962495383 values, so finally subsitute to the script arguments, and get the flag.

## Level3 (300 points)
Within this challenge a block-encryption is introduced with some padding and byte-to-int conversation functions (the little-endianness is unchanged). The word width is 4 bytes. The encryption (which was so far the byte-wise XOR) becomes a multiplication modulo 2^32.

```python
header = binascii.unhexlify("8950 4e47 0d0a 1a0a 0000 000d 4948 4452".replace(" ", ""))
header = [int.from_bytes(header[4*i:4*(i+1)], byteorder='little') for i in range(0, len(header)//4)]
data = binascii.unhexlify("9789 28bf 05a2 b4ed 0000 005f eda9 4f91".replace(" ", ""))
data = [int.from_bytes(data[4*i:4*(i+1)], byteorder='little') for i in range(0, len(data)//4)]

header
# [1196314761, 169478669, 218103808, 1380206665]
data
# [3207104919, 3988038149, 1593835520, 2437917165]
```

Writing the equations modulo 2^32, where *xi* denotes the lcg *i*th output:
```
x1 * 1196314761 = 3207104919 (mod 2^32)
x2 *  169478669 = 3988038149 (mod 2^32)
x3 *  218103808 = 1593835520 (mod 2^32)
x4 * 1380206665 = 2437917165 (mod 2^32)
```

Solving with Sage (as at the previous exercise) we get many sollutions for *x3*, but only one for the other lcg output: *x1* = 1978286367, *x2* = 155472345, *x4* = 3451731077. Because of the ambiguous *x3* value we have to replace it with *x2* (which is right beacuse of the modulo operators): `(x2 * a + c) * a + c = x4`. The result (a, c) pair should check against the `x3 *  218103808 = 1593835520 (mod 2^32)` condition, where `x2 * a + c = x3 (mod 2^32)`.
```sage
solve_mod([a * 1196314761 == 3207104919], M)
# [(1978286367,)] <- x1
solve_mod([a * 169478669 == 3988038149], M)
# [(155472345,)]  <- x2
solve_mod([a * 1380206665 == 2437917165], M)
# [(3451731077,)] <- x4

M = 2**32
solve_mod([a * x1 + c == x2, a**2 * x2 + a * c + c == x4], M)
# [(1960381802, 296732675),   -> x3 = 353546461   -> 956301312 != 1593835520
#  (187101845, 4139982030),   -> x3 = 1780212251  -> 1593835520   OK
#  (2334585493, 1992498382),  -> x3 = 1780212251  -> 1593835520   OK
#  (4107865450, 2444216323)]  -> x3 = 353546461   -> 956301312 != 1593835520

```

The command: `python pngcrypto_3.py d pngcrypto_3.png.enc out_3.png 1978286367 187101845 4139982030`

Note that this time there are two possible sollution!

## Level4 (300 points)
The file format remained the same, so let's use the previous challenge's script.
```python
header = binascii.unhexlify("8950 4e47 0d0a 1a0a 0000 000d 4948 4452".replace(" ", ""))
header = [int.from_bytes(header[4*i:4*(i+1)], byteorder='little') for i in range(0, len(header)//4)]
data = binascii.unhexlify("e8e8 51dd 8c0a 33fa e525 b5dc 4841 8051".replace(" ", ""))
data = [int.from_bytes(data[4*i:4*(i+1)], byteorder='little') for i in range(0, len(data)//4)]

header
# [1196314761, 169478669, 218103808, 1380206665]
data
# [3713132776, 4197649036, 3702859237, 1367359816]
```

Because of the XOR operator it's hard (at least for me) to find a formula as in the previous challenges. Instead let's try brute force it!
```c
#include <stdio.h>
#include <stdint.h>
// Christmas tree - because of the feeling ;)
uint32_t mod_pow_65537(uint32_t b) {
   uint32_t r;
           r=b
          ;r*=r;
        r*=r;r*=r;
       r *=r;r*= r;
      r*=r;r*=r;r*=r;
       r *=r;r*= r;
    r *=r;r *= r;r*= r;
          r *= r;
          r *= r;
          r *= r;
  return  (r *b);
}

int main() {
  uint32_t x = 0;
  uint32_t x_exp = 0;
  uint32_t h[] = {1196314761, 169478669, 218103808, 1380206665};
  uint32_t d[] = {3713132776, 4197649036, 3702859237, 1367359816};
  for (; x < 0xffffffff; ++x) {
    x_exp = mod_pow_65537(x);
    if (((h[0] * x) ^ x_exp) == d[0])
      printf("Found x1 = %llu\n", x);
    if (((h[1] * x) ^ x_exp) == d[1])
      printf("Found x2 = %llu\n", x);
    if (((h[2] * x) ^ x_exp) == d[2])
      printf("Found x3 = %llu\n", x);
    if (((h[3] * x) ^ x_exp) == d[3])
      printf("Found x4 = %llu\n", x);
  }
  // manually check for 0xffffffff...
}
```

This program runs for the 2^32 keyspace within a minute on an average computer and finds many possible *xi* values (x1: 17, x2: 17, x3: 1, x4: 33), but there is only one *x3*: *x3* = 1693001189.

Now we can reduce the problem to __Level2__ because there are 17*17 = 289 combination of (x1, x2, x3) and we just have to check their sollution against the condition which is generated by x4.

```sage
x1l = [456871589, 713510565, 897102171, 993742501, 1153741147, 1250381477, 1433973083, 1690612059, 2604355237, 2860994213, 3044585819, 3141226149, 3301224795, 3397865125, 3548043176, 3581456731, 3838095707]
x2l = [407430815, 664137313, 798297532, 879366559, 1011410591, 1136073057, 1268117089, 1483346335, 1740052833, 2554914463, 2811620961, 3026850207, 3158894239, 3283556705, 3415600737, 3630829983, 3887536481]
x3  = 1693001189
x4l = [73489953, 113156575, 423714337, 463380959, 759258657, 798925279, 811687457, 851354079, 1044645640, 1296129569, 1335796191, 1348558369, 1388224991, 1684102689, 1723769311, 2034327073, 2073993695, 2220973601, 2260640223, 2571197985, 2610864607, 2906742305, 2946408927, 2959171105, 2998837727, 3443613217, 3483279839, 3496042017, 3535708639, 3831586337, 3871252959, 4181810721, 4221477343]
var('a, c')
M = 2**32

for x1 in x1l:
  print("Find sollutions for x1 = %d" % x1)
  for x2 in x2l:
    sols = solve_mod(
      [a * x1 + c == x2, a * x2 + c == x3], M, solution_dict=True
    )
    for sol in sols:
      if ((sol[a] * x3 + sol[c]) % M) in x4l:
        print("Found sollution: x=%d, a=%d, c=%d" % (x1, sol[a], sol[c]))
  print("----")
```

Again, it also takes less then a minute and gives plenty of sollutions (32). Brute force again: write a script which decrypt with all of the 32 parametes, and check by the thumbnails which are valid. Then we can spot the right one (in fact there are 4 identical images!), and get the flag.
