MitM Challenges
===============

> Writeup for Crysys SecChallenge 2015. The original challenges are available on avatao.com.

## MitM part1 - adveRSAries (250 points)

In this challenge we get the source code of a *very basic* file server-client. The protocol something like:
 - run the `clntsrv.py` script 
 - specify the mode: 'client' or 'server'
     + client signs filenames
     + server serves properly signed files

The server mode prints the files from the current directory, so we can clearly see that `flag.txt` is our target, now we just have to ask for it. Sadly the client mode prohibit signing anything containing *flag* or *.py* because of
```python
...
if not search("flag|\\.py", f):
    srv.send(sign(f))
...
```

But for a second let's overlook the fact that signing 'flag.txt' is impossible, and instead focus on what would happen during the signing:
 - `msgNum = int(msg.encode("hex"), 16)` : string interpreted as a number
 - `sig = str(pow(msgNum, d, N))` : sig = msgNum^d (mod N)

Because of the RSA properties (see the RSA writeup for this) we can divide the msgNum into `msgNum = a * b`, then compute `sig_a = a^d (mod N)` and `sig_b = b^d (mod N)`. From these two signs we could easy get sig: `sig = sig_a * sig_b (mod N)`, thus the deisred signtaure is obtained. So we just have to factorize *msgNum* and get the two signtaures for them, then combine them togother.

```python
import binascii

msg = "flag.txt"
msgNum = int(msg.encode("hex"), 16)
# 7380380985142311028
4 * 127 * 4231 * 990329 * 3467309 
# 7380380985142311028

a = 4231 * 990329
# 4190081999
b = msgNum / a
# 1761392972

msg_a = binascii.unhexlify(hex(a)[2:])
# '\xf9\xbf\x93\xcf'
msg_b = binascii.unhexlify(hex(b)[2:])
# 'h\xfc\xb9L'
```

After obtaining the two divisors of "flag.txt", let's get their signs:
```bash
printf "client\n2\n\xf9\xbf\x93\xcf\nh\xfc\xb9L\n0\n0\n" | nc IPADDRESS PORTNUM
# Should I run as a server or a client?
# Running as client
# ....
# 6974133414703891964955894742027874365720897088983866771315778355180860238444801416964943354324750900708099555541738163240175542939201975367137356946953224403230287800976945252111025791067802675726023191886404113576757303405362105409748970025622263498039985979246224078270397065058626763209537077775809843084
# h..L
# 77930616341574143996512267274832044118970537486446568161956833587522197321903490486835632234746518602956115690923524201433084981389902697027038751187396783540434785216484046631289267545294816465594077300331570797613848212454024948806007825229728241326178483191463438813775203168264274296689455388061540381675

```

Compute sign simple multiply those two number modulo N (which can be found in `clntsrv.py`) we got: `55923405257079833935200947900874249809341201566030162658666466931048522445016904168409637528718419748197176010436388560877776635257009894523021533556833324771407655958424745770376746164206970113228691953644139595820897463452403994368064575709783576404771469310935502921017646891430180503337655760013762267536`

So let's get the flag:
```bash
printf "server\nflag.txt\n55923405257079833935200947900874249809341201566030162658666466931048522445016904168409637528718419748197176010436388560877776635257009894523021533556833324771407655958424745770376746164206970113228691953644139595820897463452403994368064575709783576404771469310935502921017646891430180503337655760013762267536\n" | nc IPADDRESS PORTNUM
```


## MitM part2 - harDHeads (300 points)

The software concept remained the same as in part1, but the crypto wrapping is new: the signing is performed via AES encryption of the filename XOR-ed with a shared secret. The shared secret is negotioned with Diffe-Hellman protocol, which uses the DH group_17 prime number (so the key-exchange part considered secure) and derived from an md5 algorith, thus it becomes 16 bytes long. The AES part of the signing mathod is also considered secure, although its parameters (key and IV) are fixed (obviously censored in the source file), but there's a weaker part to be investigated: the XOR method.

### Solution I. - the bug

We can clearly see a bug in the XOR method:
```python
def xorAndPad(str1, str2):
  ba1 = bytearray(str1)
  ba2 = bytearray(str2)
  out = bytearray(AES.block_size)
  for i in range(AES.block_size):
    b1 = ba1[i] if i < len(ba1) else 0
    b2 = ba2[i] if i < len(ba2) else 0
    out[i] = b1 ^ b2
  return bytes(out)
```
It's the range of the for-loop, which is fixed to 16 iterations. It means only the first 16 bytes are the base of the signing and the verification as well! Starting with a valid filename, `asciipig-1.txt`, craft an equvivalent filename: `././././././././asciipig-1.txt`. If we ask the client to sign this, it'll do it, but that sign only valid for the `././././././././` part. Thus easy replace the second part, and ask from the server the `././././././././flag.txt` file with the previous signing. :)


### Solution II. - the neat way

Probably the previous bug was completly unintended, and a much more elegant sollution should be exist. For the first in this challenge series let's consider why they are entitled "MitM". Man-in-the-middle attack consist of altering the communication between the parties (client-server in this case) so that he can get force information what he wants and not the client.

For this particular challenge we can play MitM, so we'll be a server for the client and a client for the server. This fact implies that there will be two seperate shared secret: one negotioned with the server (*ss1*) and one with the client (*ss2*). The sign should be something like `sig = crypt(filename XOR ss2)` and the verification would compute `ver = crypt(msg XOR ss1)`. It can be seen that if the argument of the crypto functions are the same (because of its deterministic property), `ver == sig` would be statisfied. That implies `filename XOR ss2 == msg XOR ss1`, where using XOR's properties we get: `msg == filename XOR ss1 XOR ss2`. That means we can ask the client to sign *msg* and uss that to sign *"flag.txt"*. Using this we can write a script something like this:

```python
dhPrime = [DH Group 17 - copy from the source file]
dhGenerator = 2

from socket import *
from hashlib import md5

clnt = socket(AF_INET, SOCK_STREAM)
clnt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
clnt.connect((HOST, PORT))
clnt.settimeout(1)
clntFile = clnt.makefile() 

srv = socket(AF_INET, SOCK_STREAM)
srv.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
srv.connect((HOST, PORT))
srv.settimeout(1)
srvFile = srv.makefile() 

# reuse most of the `clntsrv.py` file
def xorAndPad(str1, str2):
  ba1 = bytearray(str1)
  ba2 = bytearray(str2)
  out = bytearray(16)
  for i in range(16):
    b1 = ba1[i] if i < len(ba1) else 0
    b2 = ba2[i] if i < len(ba2) else 0
    out[i] = b1 ^ b2
  return bytes(out)

def numToBytes(num):
  f = format(num, 'x')
  l = len(f)
  f = f.zfill(l+l%2)
  return f.decode('hex')

def srvDHExchange(clnt, clntFile):
  # unimportant private keys
  prKey = 1
  clnt.send("DH pubkey:\n" + str(pow(dhGenerator, prKey, dhPrime)) + "\n")
  buf = clntFile.readline()
  buf = clntFile.readline().strip()
  clntPubKey = int(buf)
  sharedSecret = pow(clntPubKey, prKey, dhPrime)
  return md5(numToBytes(sharedSecret)).digest()
  
def clntDHExchange(srv, srvFile):
  prKey = 1
  buf = srvFile.readline()
  buf = srvFile.readline().strip()
  srvPubKey = int(buf)
  sharedSecret = pow(srvPubKey, prKey, dhPrime)
  srv.send("DH pubkey:\n" + str(pow(dhGenerator, prKey, dhPrime)) + "\n")
  return md5(numToBytes(sharedSecret)).digest()

try:
  # initialize
  print "CLIENT"
  print clnt.recv(4096)
  clnt.send("client\n")
  print "CLIENT"
  print clnt.recv(4096)

  print "SERVER:"
  print srv.recv(4096)
  srv.send("server\n")
  print "SERVER:"
  print srv.recv(4096)

  # DH key exchange
  ss1 = clntDHExchange(srv, srvFile)
  ss2 = srvDHExchange(clnt, clntFile)
  # end DH
  
  # related message computation
  print "flag=", "flag.txt".encode("hex")
  print "ss1 =", ss1.encode("hex")
  xor1 = xorAndPad("flag.txt", ss1)
  print "xor1=", xor1.encode("hex")
  print "ss2 =", ss2.encode("hex")
  xor2 = xorAndPad(xor1, ss2)
  print "xor2=", xor2.encode("hex")

  clnt.send("1\n" + xor2 + "\n")
  print "CLIENT"
  print  clntFile.readline()
  sig = clntFile.readline().strip()
  print sig
  print

  srv.send("flag.txt\n")
  srv.send(sig + "\n")

  print "SERVER:"
  print srv.recv(4096)
  print "SERVER:"
  print srv.recv(4096)
    
except Exception, e:
    print "Error:\n" + str(e)
    srv.close()
    clnt.close()
```
