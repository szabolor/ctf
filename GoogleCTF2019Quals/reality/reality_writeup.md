# Google CTF 2019 Quals --  Reality [Crypto, 279p, 24 solver]
### _by szabolor from !SpamAndHex_


## Challenge exploration

This challenge had a surprisingly short description: "Shamir did the job for you, just connect to the challenge and get the flag." Connecting to the server we got the following response without any chance of interaction:

```
> nc reality.ctfcompetition.com 1337
Here's a base32-encoded and encrypted flag: REDVHQ7SFOS76KWQXL6E3ZZU5WF35MVZTO5YSCFC6LLOMTMERH3A====
To decrypt it you need 5 coefficients. I'll only give you 3
coefficients 1: 1.0316936219100635000494411029908925462688072081704806599323092515849908659437556667730154801155515913642781192741211461499572042592175475427790598280404981714584167218470689447082926030377683295478179678491544872482927363436282008278919912819822047563568111490188802630860997659742251239703099279544717741680737239024940240909973142165723609840573188291865792326927362309279043509707983675738096207337407209837645377444085564334301954363151107876237264565349048525179511071026996531710781178762400121, 1107093118287107800605169534818149232204.112688017469141171155727647068777473839586463448618158246234404312210875742792594652766691408050926135648008119152315341587881034809755546723189282504522550963486499650269963230273176922485847833210546237828247040384424235824433495864107748206020806348146994349229755346673538287721378286641560831880450060198876839962023599369794193141175177232659054606485770590410947329864957899132727688032893476625504351812796976687351245368539571237597702003912250810678
coefficients 2: 1.1362536392651515945684009101474001143096434039288409824617242851423473232156326542520990149717187953149371061802092494894716449962713310858512607132206254270891023956099531021586825311855347512355686034508368402422479052736462471999815746388267454082363550644766474148116673849793913447798040073715594564463869947318827379580710995741253993168767599514799845049505500795563859197370159186025054980240121882244087154328715917894695579700986675870766908913437816343060416256430460027543163427402807229, 1329100912017314204884188025888856774910.7846665204711484017504221546497321556275270150170363301983059080635647281299006014466169879661466556986604305507932448445398847611907392642637610327666948627592002051447361712240747943346165101219504513224129671956919426785636213020718559879504345804005295832030863760391438412976665515287511749445150151416676270493500656072033481544638400990012598725609516333167192578300139270459901061688837209895289655845117145514176920122324430681220394230690487558952943
coefficients 3: 55.182350073510504880749514920585608494505066817845324407843031659270133860656022781993820816470047721717575961781714731342740880829868928709075837463991292108471258671388144990453693118329538967589907150942475476175231016823224693862905404066684015068735713371180616378631153854138941570765600602325704427242554323604097551802701707289217750531990109832732853831803089477297143402314695145247492308005543954625279789889563772015497409397545588587100458489379674868032882845957506776144992413549361036, 1848316614825170269236901426517768190485132910.6568204588376845139579153614380063059547813460208286479623816267168312629156328823048150527760752810310332912492027279697561288015843290691014202158784055149193057883139756684315476947451660144337944037612204323893881356507677500386414441634270025499543379532899695126475489470231198824836032728483472344096381475575662657414376883983533090979787311482998528763742657737916635317772034369741304694163453625946906410989482855894272156827990470556291637441
```

Collecting the information fragments we suspect that the used schema is Shamir's Secret Sharing. The main idea of SSS (Shamir's Secret Sharing) is to divide a secret into shares from which one would need at least n to reconstruct the secret. Technically speaking the secret is an integer number which become the 0th order coefficient of an (n-1)-degree polynomial where the other (n-1) coefficients are randomly chosen integer values. The shares are points of the function, comprised as (x, f(x)). To reconstruct without uncertainty the polynomial, (and with this also the zero-order coefficient, the secret), at least n different points (shares) are needed.

The challenge speaks about "coefficients", but in the context ("To decrypt it you need 5 coefficients. I'll only give you 3" and every coefficient consists of a pair of numbers) it is strongly suggests that those "coefficients" are actually the shares, thus the points of the secret function.

What makes the challenge a little odd is the fractional numbers, furthermore every number comprise at most 500 digits. In SSS the shares are points corresponding to x={0,1,2,3,...}, thus all integers values, furthermore an extension to SSS is to compute the function in respect of a big prime modulo. After observing those, we can guess that this challenge is a twist on SSS by computing fractional numbers as the argument of the polynomial.

It is easy to see in two trials that the function (not counting the secret) always changes, so it is not possible to combine shares from two consecutive connection to the server, so we really have to reconstruct the secret from the 3 given points.

To conclude we are looking for polynomials in the follow form: `f(x) = a0 + a1*x + a2*x^2 + a3*x^3 + a4*x^4`.


## CTF-style solutions

As for me, during a CTF my main objective to get the flag, and understand just as much background information as I need to solve the challenge. Also I don't use CAS (Computer Algebra System) daily, so that's why I turn to Wolfram Alpha instead of e.g. SAGE, PARI/GP or Matlab. Unfortunately Wolfram Alpha nowadays only accept around 200 character long queries, but this challenge requires at least six time 500 characters, so I went with the bigger brother, Wolfram Mathematica. Unfortunately I don't have license to the "real" (desktop) Wolfram Mathematica, but there is a free basic subscription model for its cloud version [https://www.wolframcloud.com] with time limited computations.

Knowing that we have to solve three of `f(x) = a0 + a1*x + a2*x^2 + a3*x^3 + a4*x^4`-shaped simultainous equation with the assumption of `ai` coefficients are integers, I just called the solve function filled with the parameters: 

`Solve[{a0+a1*x1+a2*x1^2+a3*x1^3+a4*x1^4==f1 && a0+a1*x2+a2*x2^2+a3*x2^3+a4*x2^4==f2 && a0+a1*x3+a2*x3^2+a3*x3^3+a4*x3^4==f3},{a0, a1, a2, a3, a4}, Integers]`

The result wasn't remotely similar what I expected as a solution (full with fractional numbers), so I tweaked a little bit on the constraints (again the positivity here was still assumed, but later strengthen via statistics):

`Solve[{a0+a1*x1+a2*x1^2+a3*x1^3+a4*x1^4==f1 && a0+a1*x2+a2*x2^2+a3*x2^3+a4*x2^4==f2 && a0+a1*x3+a2*x3^2+a3*x3^3+a4*x3^4==f3, a0>0, a1>0, a2>0, a3>0, a4>0},{a0, a1, a2, a3, a4}, Integers]`

And voilà, something resembling the expected solution appeared immediately:
```
{{a0 -> 244930398046150758209268296009008846612, 
  a1 -> 262277523506999057034892146058806204544, 
  a2 -> 263403213712405797546463588248938462947, 
  a3 ->  79324620862400379680576238983875123545, 
  a4 -> 197805757977986640900691077327564236581}}
```

Having the `a0` secret value we tried to XOR in two parts with the base32 decoded flag without luck. Then we tried AES, as its keys are 128bit long, just as the results. With AES-ECB we got the first half of the flag, but garbage for the second 16 bytes, and this strongly implied some kind of feedback mode, but with all-zero IV, as EBC mode worked. AES-CBC with the all-zero IV showed us the flag:

```
import base64
import hashlib
import binascii
from Crypto import Random
from Crypto.Cipher import AES

AES.new(binascii.unhexlify(hex(244930398046150758209268296009008846612)[2:].zfill(32)), AES.MODE_CBC, b'\x00'*16).decrypt(base64.b32decode('REDVHQ7SFOS76KWQXL6E3ZZU5WF35MVZTO5YSCFC6LLOMTMERH3A===='))
> b'CTF{h0w-r3al-is-y0ur-Re4l-4Real}'
```

But after CTF my main motivation to write writeups is to deepen in the field of the challenge. For the next parts I would like to introduce an other way of solving (almost pen-and-paper) without the big gun Wolfram Mathematica.


## Observing x values

By observing multiple (~1000) runs and building a statistics, we can conclude that values are mostly around 1, but never below 1! Also sometimes there are huge values, in the magnitude of 5000 or so. Plotting the histogram and the log-histogram of the x-values it seems that the probability of significantly higher than 1 is very low. After this we suspected some kind of reciprical distibution, and confirmed it by plottig the 1/x histogram and getting almost flat graph.

So knowing that the x values are generated with in the form of 1/q, where q should be [0;1) (sides are not certainly correct), let's observe the reciprocal values as well! We went with python, and to achieve the 500 digit precision, we used the decimal module: `from decimal import *; getcontext().prec = 500`. So based on the numbers in the beginning of the writup we'd got:
```
>>> x1 = Decimal("1.0316936219100635000494411029908925462688072081704806599323092515849908659437556667730154801155515913642781192741211461499572042592175475427790598280404981714584167218470689447082926030377683295478179678491544872482927363436282008278919912819822047563568111490188802630860997659742251239703099279544717741680737239024940240909973142165723609840573188291865792326927362309279043509707983675738096207337407209837645377444085564334301954363151107876237264565349048525179511071026996531710781178762400121")
>>> 1/x1
Decimal('0.96928000596593166804382235568482428789138793945312499999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999')
```

Those 9 digits are very suspicious, implying that the actual q number has a much lower resolution that the given x values. With computing the approximate (rounding those final runs of 9s) reciprocials we found that there are at most 53 useful digits. By multiplying the numbers and checking the Greatest Common Divisor for all of them, we found that number is 11102230246251565404236316680908203125, which is exactly 5^53 = 10^53/2^53. That means actually all of the q values are derived from the form p/2^53, where p is a random number on [0;2^53). later found out that python itself uses 53bit internal randomness to construct floating point numbers on [0;1) [https://github.com/python/cpython/blob/master/Modules/_randommodule.c#L157], and this is because the double precision has a 53 bit of significant precision.

All in all that means we don't have to rely on the imprecise 500 digit fractional numbers, instead we can compute the source of the derivation exactly! At least that's the plan, but if the calculation are internally truncated to the 500 digits after every operation, even though we have the exact 1/x values, we don't know anything about f(x) values, as there is an information loss (computing with all integer solutions, there could be a small error).


## Observing f(x) values

Again doing some statistics we found that the function always monotonically increasing, as greate x values caused greated f(x) value in the scope of a single batch of 3 points. That monotonically increasing property implies that all of the polynomial coefficients are positive.

For the magnitude of the coefficients we proposed that all of the coefficients are generated uniformly from a bounded, common range, thus in average the following formula can be used to estimate the magnitude of a single coefficient: `math.log2(f(x)/(1+x+x*x+x*x*x+x*x*x*x))`. The result is around 125-128, meaning that the coefficients are in the range of [0; 2^128]. This make sense, because 128 bit is a beloved size for key, just what we are longing for! (For now, don't mind the fact that the key is 32byte long)


## Diophantine equations

By now with the knowledge of the 53bit random source, we can reshape the original three equations from inexact fractional to exact integer calculations, simply by taking the reciprocal values of x, multiplying it by 2^53 and rounding to the nearest integer:

```
(original)                   a0 + a1*x1 + a2*x1^2 + a3*x1^3 + a4*x1^4 = f1
(substitute random source)   a0 + a1*(2^53/q1) + a2*(2^53/q1)^2 + a3*(2^53/q1)^3 + a4*(2^53/q1)^4 = f1
(to common denominator)      a0*q1^4 + a1*2^53*q1^3 + a2*2^106*q1^2 + a3*2^159*q1 + a4*2^212 = f1*q1^4
```

Using the common denominator to multiply the whole equation we got a purely integer equation, in other words Diophantine equation. This pure integer operations opens the possibility of a vastly different mathematical apparatus.

With three linear equations we can reduce the initially five unknowns to two, thus expressing the `a0` (the secret) coefficient with e.g. `a3` and `a4`. As for a little cheat (I promised pen-and-paper), use some CAS to do the reduction, so the new equation after some massage should be something like this:
```
(q1^2*(q1 - q2)*q2^2*(q1 - q3)*(q2 - q3)*q3^2) * a0 + 730750818665451459101842416358141509827966271488*(q1 - q2)*(q1 - q3)*(q2 - q3)*q1*q2*q3 * a3 + 6582018229284824168619876730229402019930943462534319453394436096*(q2^2*(q2 - q3)*q3^2 + q1^3*(q2^2 - q3^2) + q1^2*(-q2^3 + q3^3)) * a4 = q1*q2*q3*(q1*q2*q3*(f1*q1^2*(q2 - q3) + f3*(q1 - q2)*q3^2 + f2*q2^2*(-q1 + q3)))
```

Let's denote the current coefficient to `a0, a3, a4` with `A, B, C` in this order and `D` should be the constaint part, furthermore let's substitute the known values to obtain the constaints numerically:

```
A*a0 + B*a3 + C*a4 == D
A = 124619560330861393008971413318279114716464479666758578950712689673616414490131899516777761
B = 8061436540947981759216186680062280531443669719360675377492241491678702683349333674614063104
C = 462325782568067108184541062024544760381491956756612103104422350305377261323411350758302416896
D = 92120695369375530663141932926284908738257444236809426623898198702457460005979487122187489231218466536275216284179406652477203651988
```

This is a 3 variable Diophantine equation because every constant and variable are integer. Solving a Diophantine equation could be done with the help of the extended Euclidean algorithm. There is a quite good hands-on description at [https://math.stackexchange.com/questions/514105], which I followed. After the computation we have `ua, ub, uc` and of course `gcd(A,B,C)`, so that `A*ua + B*ub + C*uc = gcd(A,B,C)`. (Because the previous simplifications `gcd(A,B,C) == 1`, but it also works without the simplification.)

```
ua = -1164649617846875436469274344727615783112156985037666615876172094348157304347401245973958323487767172023488817367473240430318361425206522143
ub = 18004002460151586490152447341893036092650799529752491464661787048630964087308676062894891050071766973397362961122611644386699423726622098
uc = 83071408505821970001862088604635456327948792
gcd(A,B,C) = 1
```

Now extend that exact `gcd(A,B,C)` solutions triplet to `D` by multiplying with `D/gcd(A,B,C)`, and also add uncertancy constaints:

```
A*(ua*D/gcd(A,B,C)+k*B+l*C) + B*(ub*D/gcd(A,B,C)-k*A+m*C) + C*(uc*D/gcd(A,B,C)-l*A-m*B) = D
```

Now let's use the bounded property, namely `0<=x,y,z<2^128`, thus `0<=(ua*D/gcd(A,B,C)+k*B+l*C)<2^128`. The `ua*D/gcd(A,B,C)` expression is constant, so the value can be "shifted" by `k*B+l*C`. And what is the "step-size" of `k*B+l*C`? Clearly `gcd(B, C)`! Those are great numbers, we are still not sure it could be fit under 2^128, so for a baseline let's find the smallest positive solution for `a0` by taking the remainder of `k*B+l*C` respect to `gcd(B, C)`.

```
ua*D/gcd(A,B,C) = -107288332657731639414792970732633113515344219595310312358021398909434789117275508793282828537204174776423856282723890794021305681212278866081236971868003597321210490891476756802304017509358999536731935515988780154920392814012929508434636659394721867840152119755987970284
gcd(B, C) = 22835963083295358096932575511191922182123945984
ua*D/gcd(A,B,C) % gcd(B, C) = 244930398046150758209268296009008846612
```

The result `244930398046150758209268296009008846612` fits tightly into the 128bit limit, furthermore we can see that there is no other candidate (as the step size is `22835963083295358096932575511191922182123945984`), thus we can state without uncertainty that the "secret coefficient" is `244930398046150758209268296009008846612`. (To obtain the flag follow the script given under the "CTF-style solution" section)


## Notes

For some values it could happen that e.g. `gcd(B,C) = 1`, thus it can obtain any value in the [0;2^128) range. In this case maybe the others (`gcd(A,C)`, thus `a3` or `gcd(B,C)`, thus `a4`) can be other than `1`, and if not, we can express other variables, not only `a0,a3,a4`!

The numerical stability with the `f(x)` computations could have been a problem, but thanks to the 500 digit places, it's precision surpassed the required `~2^400-2^500` computation precision; so probably that's why this method worked.

Furthermore based on `f(x)` stability, probably one could use `x` as-is (without the reciprocal exact integer substitution), but I didn't know that in advance, thus computed with the reciprocal values.