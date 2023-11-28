---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/r8G7mVS.png
points: 400
solves: 4379
tags: forensics disk openssl
date: 1337-11-27
comments: false
---

Download this disk image and find the flag.  
Note: if you are using the webshell, download and extract the disk image into /tmp not your home directory.  
[Download compressed disk image](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/orchiddisk.img.gz)  

---

The file is `disk.flag.img.gz`, meaning it is gzipped. Unzip it with `gunzip disk.flag.img.gz` → `disk.flag.img`  
Let’s use *SleuthKit* tools to explore the disk.  
`mmls disk.flag.img`  
```
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   Linux (0x83)
003:  000:001   0000206848   0000411647   0000204800   Linux Swap / Solaris x86 (0x82)
004:  000:002   0000411648   0000819199   0000407552   Linux (0x83)

```
The Linux (0x83) partitions are the only ones we need to worry about, so let’s check those out.  
`fls -o 2048 disk.flag.img`  
```
d/d 11: lost+found
r/r 12: ldlinux.sys
r/r 13: ldlinux.c32
r/r 15: config-virt
r/r 16: vmlinuz-virt
r/r 17: initramfs-virt
l/l 18: boot
r/r 20: libutil.c32
r/r 19: extlinux.conf
r/r 21: libcom32.c32
r/r 22: mboot.c32
r/r 23: menu.c32
r/r 14: System.map-virt
r/r 24: vesamenu.c32
V/V 25585:      $OrphanFiles
```

This doesn’t look very promising. Let’s take a look at the second partition.  
`fls -o 411648 disk.flag.img`  
```
d/d 460:        home
d/d 11: lost+found
d/d 12: boot
d/d 13: etc
d/d 81: proc
d/d 82: dev
d/d 83: tmp
d/d 84: lib
d/d 87: var
d/d 96: usr
d/d 106:        bin
d/d 120:        sbin
d/d 466:        media
d/d 470:        mnt
d/d 471:        opt
d/d 472:        root
d/d 473:        run
d/d 475:        srv
d/d 476:        sys
d/d 2041:       swap
V/V 51001:      $OrphanFiles
```

This looks a lot better!  
As a general rule of thumb, I always check home and root. home is empty, but root contains the following:  
```
r/r 1875:       .ash_history
r/r * 1876(realloc):    flag.txt
r/r 1782:       flag.txt.enc
```


We have 3 files (as evidenced by the `r/r`), one of which, `flag.txt`, appears to have been removed, i.e. its memory reallocated. Let’s check out the two other files still existing.  
`icat -o 411648 disk.flag.img 1875`  
<pre>
touch flag.txt
nano flag.txt 
apk get nano
apk --help
apk add nano
nano flag.txt 
openssl
<b>openssl aes256 -salt -in flag.txt -out flag.txt.enc -k unbreakablepassword1234567</b>
shred -u flag.txt
ls -al
halt
</pre>

This appears to show the history of the commands executed here. As we noted previously, the `flag.txt` file was removed, as evidenced by the `shred -u flag.txt`. Meanwhile, the important (bolded) command appears to show that `flag.txt` was encrypted using the aes256 encryption scheme with the option -salt and a password of *unbreakablepassword1234567*.  
Let’s check out the .enc file.  
`icat -o 411648 disk.flag.img 1782`  
```
Salted__S+%+Okђ(Ac
                  @]ԣ
ޢȤ7 ؎$'%
```

As you might expect, this doesn’t appear to tell us anything relevant, only that the -salt is likely a necessary option for decrypting.  
To work with this encrypted file, let’s put it in our local machine.  
`icat -o 411648 disk.flag.img 1782 > enc`  
Now, let’s try and reverse the encryption command.  
`openssl aes256 -d -salt -in enc -out flag.txt -k unbreakablepassword1234567`  
Note that -d simply tells openssl to decrypt, rather than encrypt, the input file.  


<pre 
  class="command-line" 
  data-prompt="kali@kali $" 
  data-output="2"
><code class="language-bash">cat flag.txt
picoCTF{h4un71ng_p457_1d02081e}</code>
</pre>