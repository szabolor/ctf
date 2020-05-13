# Tokyo Westerns 2019 Quals - Simple Logic - Crypto

For this challenge a Ruby script and the encrypted flag were given, so our task was to revert the encryption.

The ruby script is used for both the encryption and also the decryption part.
The following is in the heart of the encryption schema:

```
def encrypt(msg, key)
    enc = msg
    mask = (1 << BITS) - 1
    ROUNDS.times do
        enc = (enc + key) & mask
        enc = enc ^ key
    end
    enc
end
```

There are two quite simple operations: an addition and a XOR both performed with the secret key.
The problem with this schema is it's linearity, which in this case occures in a special way:
reducing the mask width, an n-LSB bit also becomes a solution for the reduced equations!

First let's observe the LSB bit for all of the operations (act like there's a single bit-width mask instead of the 128),
and write the truth-table for those values:

|msg[0] | key[0] | enc[0]|
|-------|--------|-------|
|  0    |   0    |   0   |
|  0    |   1    |   0   |
|  1    |   0    |   1   |
|  1    |   1    |   1   |
  
As we can see, just by the encrypted output we can tell apart the msg[0]=0 and msg[0]=1 cases, although the key bit remain unknown. But continuing with a 2-bit wide mask and using our current knownledge of msg[0], we can guess from bit 1 to key[0], thus effectively cracking a single bit!

Although one can do this bit-by-bit, it was easier for me to think in byte units, that's why my solver written in Julia is based on brute-forcing the 256 combinations for a byte then move on to the next one.

```
function do_encrypt(msg, key)
    enc = msg
    for i = 1:765
        enc = xor((enc+key), key)
    end
    enc
end

function do_decrypt(msg, key)
    enc = msg
    for i = 1:765
        enc = xor(enc, key) - key
    end
    enc
end

plain = [
    UInt128(0x029abc13947b5373b86a1dc1d423807a),
    UInt128(0xeeb83b72d3336a80a853bf9c61d6f254),
    UInt128(0x7a0e5ffc7208f978b81475201fbeb3a0),
    UInt128(0xc464714f5cdce458f32608f8b5e2002e),
    UInt128(0xf944aaccf6779a65e8ba74795da3c41d),
    UInt128(0x552682756304d662fa18e624b09b2ac5),
]

encrypted = [
    UInt128(0xb36b6b62a7e685bd1158744662c5d04a),
    UInt128(0x614d86b5b6653cdc8f33368c41e99254),
    UInt128(0x292a7ff7f12b4e21db00e593246be5a0),
    UInt128(0x64f930da37d494c634fa22a609342ffe),
    UInt128(0xaa3825e62d053fb0eb8e7e2621dabfe7),
    UInt128(0xf2ffdf4beb933681844c70190ecf60bf),
]

function search(keyinit, keyinitwidth, bitwidth)
    key_step = UInt128(UInt128(1)<<keyinitwidth)
    key = UInt128(keyinit)
    mask = UInt128((UInt128(1)<<bitwidth)-1)
    println("Key init: ", string(keyinit, base=16))
    println("Key step: ", string(key_step, base=16))
    println("Mask: ", string(mask, base=16))

    for i = 1:(1<<(bitwidth-keyinitwidth))
        key += key_step

        if     (encrypted[1] & mask) != (do_encrypt(plain[1], key) & mask)
            continue
        elseif (encrypted[2] & mask) != (do_encrypt(plain[2], key) & mask)
            continue
        elseif (encrypted[3] & mask) != (do_encrypt(plain[3], key) & mask)
            continue
        elseif (encrypted[4] & mask) != (do_encrypt(plain[4], key) & mask)
            continue
        elseif (encrypted[5] & mask) != (do_encrypt(plain[5], key) & mask)
            continue
        elseif (encrypted[6] & mask) != (do_encrypt(plain[6], key) & mask)
            continue
        end

        println("FOUND: ", string(key, base=16))
        break
    end
    key
end


function stepping()
    key = search(UInt128(0), UInt128(0), 8)
    for bw = 16:8:128
        key = search(key, bw-9, bw)
    end
end
```
