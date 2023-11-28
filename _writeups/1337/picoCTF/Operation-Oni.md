---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/4W3CcYR.png
points: 300
solves: 2790
tags: forensics disk permissions
date: 1337-11-27
comments: false
---

Download this disk image, find the key and log into the remote machine.  
Note: if you are using the webshell, download and extract the disk image into /tmp not your home directory.  
[Download disk image](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/picoCTF/onidisk.img.gz)
Remote machine: ssh -i key_file -p [port #] ctf-player@saturn.picoctf.net

---

We are given a file `disk.img.gz`
The `.gz` file extension indicates that the file is a gzip compressed file → `gunzip disk.img.gz` decompresses the file  
*SleuthKit* is a useful tool for disk forensics  
`mmls disk.img`
```
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   Linux (0x83)
003:  000:001   0000206848   0000471039   0000264192   Linux (0x83)
```
Checking the first partition with `fls -o 2048 disk.img`
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
Checking the second partition with `fls -o 206848 disk.img`
```
d/d 458:        home
d/d 11: lost+found
d/d 12: boot
d/d 13: etc
d/d 79: proc
d/d 80: dev
d/d 81: tmp
d/d 82: lib
d/d 85: var
d/d 94: usr
d/d 104:        bin
d/d 118:        sbin
d/d 464:        media
d/d 468:        mnt
d/d 469:        opt
d/d 470:        root
d/d 471:        run
d/d 473:        srv
d/d 474:        sys
V/V 33049:      $OrphanFiles
```

The second partition looks promising.
Checking `home` with `fls -o 206848 disk.img 458` returns nothing.  
Checking `root` with `fls -o 206848 disk.img 470` returns  
```
r/r 2344:       .ash_history
d/d 3916:       .ssh
```

`.ash_history` is a file (identified by `r/r`)  
`.ssh` is a directory (identified by `d/d`)  
`icat -o 206848 disk.img 2344` outputs the `.ash_history`  
```
ssh-keygen -t ed25519
ls .ssh/
halt
```


Thus, we know the directory `.ssh` is a result of an `ssh-keygen` of type `ed25519`  
`fls -o 206848 disk.img 3916` outputs the files of `.ssh`  
```
r/r 2345:       id_ed25519
r/r 2346:       id_ed25519.pub
```


`icat -o 206848 disk.img 2345` outputs the `id_ed25519 file`  
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBgrXe4bKNhOzkCLWOmk4zDMimW9RVZngX51Y8h3BmKLAAAAJgxpYKDMaWCgwAAAAtzc2gtZWQyNTUxOQAAACBgrXe4bKNhOzkCLWOmk4zDMimW9RVZngX51Y8h3BmKLAAAAECItu0F8DIjWxTp+KeMDvX1lQwYtUvP2SfSVOfMOChxYGCtd7hso2E7OQItY6aTjMMyKZb1FVmeBfnVjyHcGYosAAAADnJvb3RAbG9jYWxob3N0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```


`icat -o 206848` disk.img 2346 outputs the `id_ed25519.pub file`  

`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGCtd7hso2E7OQItY6aTjMMyKZb1FVmeBfnVjyHcGYos root@localhost`


This appears to show the private key and public key, respectively.

`icat -o 206848 disk.img 2345 > private_key` saves the private key to a file in your local machine

`ssh -i private_key -p [port #] ctf-player@saturn.picoctf.net` returns  
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for 'private_key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "private_key": bad permissions
```

This is telling us that `private_key`’s access permissions are too open since others can read and write files, which we can confirm with the command `ls -ld private_key`, which shows the permissions of ```-rw-rw-r--```. Essentially, we want to modify this into ```-rw-------```. We can do this via `chmod 600 private_key`. Using ```ls -ld private_key``` again confirms that the permissions of the file is now ```-rw-------```.  

```ssh -i private_key -p [port #] ctf-player@saturn.picoctf.net``` now gets us into the file system.  

<code class="language-bash">
ls
cat flag.txt
picoCTF{k3y_5l3u7h_339601ed}
</code>