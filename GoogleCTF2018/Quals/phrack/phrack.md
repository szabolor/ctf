# GoogleCTF 2018 Quals - Phrack [Misc, 420p, 5 solver] writeup
### _by !SpamAndHex_

The Phrack challenge was released in the "Misc" category with the very brief description: "I heard Phrack is still kinda relevant. But since when do they include ctf flags?". Unfortunately - due to belonging to the relatively younger generation - I wasn't even aware of this great journal (or "ezine") till now... (editor's note: way to make the proofreader feel very old, buddy!)

The only attachment was an ARJ compressed file (`PHRAKIDX.ARJ`). After extracting it, a single `PHRAKIDX.TXT` file is generated, which is an index file for the first 47 issue of Phrack. Searching on the Internet for the name of the given file, some archives can be easily found, like [http://cd.textfiles.com/phoenixrising/phrack/phrakidx.arj] - let's call it the original file. After extraction those archives have exactly the same content as our file, but the initial ARJ files are different.

First of all the given ARJ file is larger than the original one: 10779 versus 9031 bytes. Inspecting with the arj command we can see one potential source of the size difference:

```
> arj v PHRAKIDX.ARJ 
ARJ32 v 3.10, Copyright (c) 1998-2004, ARJ Software Russia. [04 Jun 2018]

Processing archive: PHRAKIDX.ARJ
Archive created: 1970-01-01 01:00:00, modified: 1970-01-01 01:00:00
<THE SAME FANCY HEADER REMOVED>
Sequence/Pathname/Comment/Chapters
Rev/Host OS    Original Compressed Ratio DateTime modified Attributes/GUA BPMGS
------------ ---------- ---------- ----- ----------------- -------------- -----
001) PHRAKIDX.TXT
  6 MS-DOS        30439      10290 0.338 70-01-01 01:00:00                  4  
------------ ---------- ---------- -----
     1 files      30439      10290 0.338 

> arj v orig/phrakidx.arj  
ARJ32 v 3.10, Copyright (c) 1998-2004, ARJ Software Russia. [04 Jun 2018]

Processing archive: orig/phrakidx.arj
Archive created: 1993-07-04 20:46:02, modified: 1993-12-10 20:38:32
<HERE THE PREVIOUS FANCY HEADER REMOVED>
Sequence/Pathname/Comment/Chapters
Rev/Host OS    Original Compressed Ratio DateTime modified Attributes/GUA BPMGS
------------ ---------- ---------- ----- ----------------- -------------- -----
001) PHRAKIDX.TXT
  6 MS-DOS        30439       8542 0.281 93-07-04 20:45:28                  1  
------------ ---------- ---------- -----
     1 files      30439       8542 0.281

```

So besides the dates, the BPMGS indicates a difference. Although there's no direct reference in the man pages or readmes for the meaning of BPMGS, it is the "method" flag: basically a compression level, where 1=highest, 4=lowest and 0=none compression. Thus the higher compression rate of the original file may explain the size difference, but let's investigate further! What if we recompress the TXT content using "Method 4" (`arj a -m4 method4.arj PHRAKIDX.TXT`)? Still there's a subtle size difference in the compression size: 9698 versus the desired 10290 (for this metric use the verbose output of arj, because the original file are created in addition with a fancy header commenct section).

```
> arj v create_m4.arj 
ARJ32 v 3.10, Copyright (c) 1998-2004, ARJ Software Russia. [04 Jun 2018]

Processing archive: create_m4.arj
Archive created: 2018-06-24 16:32:35, modified: 2018-06-30 11:11:01
Sequence/Pathname/Comment/Chapters
Rev/Host OS    Original Compressed Ratio DateTime modified Attributes/GUA BPMGS
------------ ---------- ---------- ----- ----------------- -------------- -----
001) PHRAKIDX.TXT
 11 UNIX          30439       9698 0.319 79-11-30 00:00:00 -rw-r--r-- ---   4  
                                   DTA   18-06-23 12:08:19
                                   DTC   18-06-24 16:30:49
------------ ---------- ---------- -----
     1 files      30439       9698 0.319 
```

Seeing that we had two ideas:
 - there is extra data in the given compressed data, which is somehow not processed by the extraction algorithm
 - for some reason the used compression algorithm was less efficient than in arj v3.10, which we used here

Those ideas required deeper understanding of the ARJ compression, but unfortunately we haven't found any clear and concise descriptions of the ARJ algorithms. On the other hand we have the open-source ARJ implementing those algorithms so maybe it is enough to "decorate" a little the source for our purposes!


Compiling an open-source program may seems trivial, but - at least for me - it wasn't. The software at [http://arj.sourceforge.net/] is quite old, the currently used arj utilities are built around the most recent 3.10.22 version released in 2005! (Fun fact: 3.10.22 was released on 2005.06.23., EXACTLY 13 years before the ctf!)
As I'm an Archlinux user I turned to the arch repository [https://git.archlinux.org/svntogit/community.git/tree/trunk?h=packages/arj] which made possible the compilation.

Getting an overview of the codebase of arj, we could see that the interesting decryption function is in `decode.c` and called `decode_f`. Here is a commented excerpt:

```c
/* Decodes the entire file, using method 4 */
void decode_f(int action) {
 int i, j, c, r;
 static unsigned long ncount;

 // currently the text is less than the dictionary size
 // so ntext is the decompressed output
 if(ntext==NULL)
  ntext=malloc_msg(FDICSIZ); // dictionary size
 decode_start_stub();
 display_indicator(0L);
 ncount=0L; // current byte position in the decompressed output
 r=0;
 while(ncount<origsize) {
  // read the next "chunk" of ARJ block (this is just my concept, probably has a proper name)
  c=decode_len();

  if(c==0) {
   // only a single character decoded
   ncount++;
   ntext[r]=(unsigned char)(bitbuf>>8);
   fillbuf(8);
   if(++r>=FDICSIZ) {
    r=0;
    display_indicator(ncount);
    if(extraction_stub(ntext, FDICSIZ, action))
     goto termination;
   }
  } else {
   // "backreference" to a previous block of data in the dictionary
   j=c-1+THRESHOLD;
   ncount+=(unsigned long)j;
   if((i=r-decode_ptr()-1)<0)
    i+=FDICSIZ;
   while(j-->0) {
    ntext[r]=ntext[i];
    if(++r>=FDICSIZ) {
     r=0;
     display_indicator(ncount);
     if(extraction_stub(ntext, FDICSIZ, action))
      goto termination;
    }
    if(++i>=FDICSIZ)
     i=0;
   }
  }
 }
 if(r>0)
  extraction_stub(ntext, r, action);
 termination:
 decode_end_stub();
 free(ntext);
 ntext=NULL;
}
```

Firstly examine if there is any extra data left in the compressed stream. The ARJ verbose states that it has 10290 byte of compressed data, and indeed dissecting the file with the ARJ file format (http://www.opennet.ru/docs/formats/arj.txt) there is no extra data remaining at the end of the file.
Secondly investigate that every compressed byte somehow results in an decompressed byte: in the `fillbuf` function we can simply hook the `compsize` variable: `printf("DEBUG fillbuf(%d), bitcount: %d, compsize: %d\n", n, bitcount, compsize);` and in `decode_f` do the same with `ncount`. But after extraction we only get a boring, monotonic increasing order of `ncount` and a decreasing of `compsize`, furthermore each of them reach their end points: 10290 for the decompressed and 0 for the remaining compressed size. Thus this was a dead-end.

Continuing with our other theory, the "bad compression" path, now instead of the counters, let's hook the decompressed output segments. Simply put a `printf("single: %c\n", ntext[r]);` into the sigle character case and `printf("block: "); while(j-->0) { printf("%c", ntext[i]); ... } printf("\n");` into the block case. Examining the result we get the fairly typical compression properties:

```
block: . Acronyms Part I
single: V
block:  by Firm G.R.A.S.P.            
block:           52K
2
single: 5
block: . Acronyms Part 
block: V by Firm G.R.A.S.P.            
```

Notice how the dictionary "learns" that a "V" and "by Firm G.R.A.S.P." can be grouped together into "V by Firm G.R.A.S.P.". So for the given file the compression worked indeed, that's why it was very strange to withness rows like these:

```
block: Phrack
block:  World News I
single: V
block:  Part 1
block:  by Knight Lightning
11.
single:  
single: P
single: h
single: r
single: a
single: c
single: k
block:  World News IV
block:  Part 2 by Knight Lightning
```

Here "Phrack" (which occures 203 times in the text) is somehow not compressed at all, and there are other places where this happens! It seems too specific to be by chance, so we have got to be on the right track! Now collect the compression-variations of the word "Phrack" using a little state machine:

```c
static int phrack_idx = 0;
char phrack[] = "Phrack";

// to single character part
if (ntext[r] == phrack[phrack_idx++]) {
 if (phrack_idx == 6)
  printf("DEBUG: Phrack serial trigger\n");
 } else {
 phrack_idx = 0;
}

// to block part
if (ntext[r] == phrack[phrack_idx++]) {
  if (phrack_idx == 6)
   printf("DEBUG: Phrack block trigger\n");
 } else {
  phrack_idx = 0;
}

```

Getting the output and verifing we have exactly 203 rows of triggers, let's substitute 1 for "DEBUG: Phrack serial trigger" and 0 for the other - as the serial/block coded text has one bit of information. Arranging into bytes we got the following stream of bits:

```
11000010
00101010
01100010
11011110
10101100
01100110
01100110
10101100
10011100
01001100
10101100
01100110
10000110
10000110
10011100
00100110
10001100
10100110
11001100
10011100
01101100
01100110
10101100
01101100
10111110
000
```

It is easy to see that the last bit of every group is zero, and the 6th bit is almost always 1 except the first three bytes. This strongly implies ASCII characters with the bit order reversed. A one-liner in python:

```python
bits = "11000010001010100110001011011110101011000110011001100110101011001001110001001100101011000110011010000110100001101001110000100110100011001010011011001100100111000110110001100110101011000110110010111110000"
''.join(map(lambda s: chr(int(s,2)), [bits[i:i+8].zfill(8)[::-1] for i in range(0,len(bits), 8)]))
```

And it finally returns the flag: `CTF{5ff5925faa9d1e396f56}` :)

