---
layout: writeup
category: Backdoor-CTF-2024
chall_description: 
points: 100
solves: 46
tags: forensics password-cracking hashcat rockyou
date: 2024-12-24
comments: false
---

I forgot my Browser's saved password although a friend of mine tells that I can find it if I know my master key. The problem is I dont even remember that, hopefully you can rock your brain and help me out.  

Author: W01f  

[chal.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Backdoor-CTF-2024/chal.zip)  

---

### firefox will rock your world

We're provided 3 files:  
- `cert9.db`  
- `key4.db`  
- `logins.json`  

A little bit of research tells us that these files are typical of a Firefox profile:  
- `cert9.db` stores Firefox certificates  
- `key4.db` stores information regarding the master password, which basically requires the user to input a password to view the saved website passwords  
- `logins.db` stores **encrypted** website passwords, decrypted using the master password  

After backing up my own versions of these files, I copied the challenge files into my local Firefox profile, which can be accessed by navigating to `about:support` on Firefox and going to `Application Basics -> Profile Folder -> Open Folder`. Opening up Firefox, however, I found that the password manager was protected by a master password (as explained in the challenge statement).  

Seeing this, I realized that I likely had to crack the master password. The challenge description gave a hint towards this, saying "hopefully you can **rock your** brain and help me out." This is evidently a reference to the `rockyou.txt` password wordlist!  

### tool searching galore yay fun

I started doing some research into tools that could crack the Firefox master password. The first one I stumbled across was [FireMaster](https://securityxploded.com/firemaster.php). However, this tool proved to be way too slow (it would probably take at least a day to process the entire rockyou.txt wordlist!), so I kept looking. I soon realized that `hashcat` had a hash mode for this, so I simply needed to extract the password from `key4.db`.  

Unfortunately, there seemed to be limited resources describing how to do this. Although FireMaster is open-source, I couldn't seem to find the source code of it, as I would have liked to see how FireMaster extracted the hashed master password. I read through [this article](https://apr4h.github.io/2019-12-20-Harvesting-Browser-Credentials/), but the method it described for extracting the master password failed for me. I found [this tweet](https://x.com/lorenzo2472/status/1383757827332661255?lang=en) linking to a tool called [Firepwd.py](https://github.com/lclevy/firepwd), which ultimately did not help me extract the master password, and a [hashcat commit](https://github.com/Banaanhangwagen/hashcat/commit/ee7d8ef0e72e62d77cc0fcc3719c759c447be757#diff-8419d9a38af3b108ee6855e19df739db51761224dfe2fe0fb62ddb0c41b28136) that added support for the Firefox master password. This commit wasn't useful for finding out how to extract the passwords, but it did provide some information that would become useful in the future: the code in [line 83 of tools/test_modules/m26100.pm](https://github.com/Banaanhangwagen/hashcat/commit/ee7d8ef0e72e62d77cc0fcc3719c759c447be757#diff-0f8ebb43b4076701d8b0d679b52ae6186b503837360db2ba226529ba500854b0R83) showed how the hash should be formatted, based on the two salts, iteration number (which I guessed was just 10000 since that's what it was on the [hash mode example database](https://hashcat.net/wiki/doku.php?id=example_hashes) for `Mozilla key4.db`), IV, and ciphertext.  

### tysm random github user i love you

I, of course, looked at John the Ripper as well, but, unfortunately, it only worked for `key3.db`, as written [here](https://github.com/openwall/john/blob/bleeding-jumbo/doc/README.mozilla). I still tried it locally on the `key4.db`, but to no avail. Later, however, I found an [issue](https://github.com/openwall/john/issues/5160) on the Github repo that described the exact same problem. [AlbertVeli](https://github.com/AlbertVeli) actually made his own Python program to do exactly that! Well, at least mostly. It didn't exactly reconstruct the master password hash in the form hashcat wanted it to be in.  

FYI, here's that program:  
```py
#!/usr/bin/env python3

# Helper for cracking Mozilla key4.db password database master password.
#
# Algorithm:
# * 20 byte db_salt and ~133 byte DER-encoded ciphertext
#   are extracted from key4.db
# * The ciphertext is then decoded and a number of parameters
#   extracted from it:
#   - Algorithm OIDs, only pbkdf2_hmac_sha256 supported right now
#   - Salt for pbkdf2_hmac
#   - encryption algorithm (only aes256-cbc supported right now)
#   - IV for AES decryption
#   - Ciphertext for AES
# * Loop pw candidates in john, for each pw:
#   - AES_key = pbkdf2_hmac_sha256(sha1(db_salt + pw), decoded_salt, iterations)
# * Decrypt the AES ciphertext with the key and IV
# * If the decrypted result is b'password-check' then
#   the guessed password was correct.

import sys
import sqlite3
import hashlib
import binascii

try:
    import asn1
except:
    print('module asn1 not found, try: pip install asn1')
    exit(1)

# The following imports are just for the test at the end
import hmac
from Crypto.Cipher import AES

oids = []
bstrings = []
ints = []

def recurse_asn1(input_stream):
    """
    Recurse through ASN.1 structure and save
    interesting values in global variables
    """
    global oids, bstrings, ints

    while not input_stream.eof():
        tag = input_stream.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = input_stream.read()
            if tag.nr == 6:
                # oid
                oids.append(value)
            elif tag.nr == 4:
                # octet string (byte array)
                bstrings.append(value)
            elif tag.nr == 2:
                # integer
                ints.append(value)

        elif tag.typ == asn1.Types.Constructed:
            input_stream.enter()
            recurse_asn1(input_stream)
            input_stream.leave()

def parse_asn1(ciphertext):
    """
    Parse the asn1 byte array
    Based on the dump.py example
    from https://github.com/andrivet/python-asn1/
    """
    decoder = asn1.Decoder()
    decoder.start(ciphertext)
    recurse_asn1(decoder)

# Hexdump python3 byte string
def hexdump(bs):
    print(binascii.hexlify(bs).decode())


# --- main program ---


# Path to key4.db in first argument
if len(sys.argv) != 2:
    print('Usage: ' + sys.argv[0] + ' </path/to/key4.db>')
    exit(1)
db_path = sys.argv[1]

con = sqlite3.connect(db_path)
cur = con.cursor()
cur.execute('SELECT * from metaData WHERE id="password"')
res = cur.fetchall()[0]
con.close()

# res = (id, item1,  item2)
# item1 is 20 bytes salt
# item2 is DER-encoded ciphertext
db_salt = res[1]
print('database salt:')
hexdump(db_salt)
ciphertext = res[2]
print('database ciphertext:')
hexdump(ciphertext)


print('')

# Decode ciphertext
parse_asn1(ciphertext)

# Check if format supported
# TODO: Support more algorithms
#       For now only this specific
#       cipher suite is supported
expected_oids = (
 '1.2.840.113549.1.5.13',  # PKCS5 PBES2
 '1.2.840.113549.1.5.12',  # PKCS5 PBKDF2
 '1.2.840.113549.2.9',     # hmacSHA256
 '2.16.840.1.101.3.4.1.42' # aes256-CBC
 )
for i in range(len(expected_oids)):
    if expected_oids[i] != oids[i]:
        print('Expected OID', expected_oids[i],
              'got OID', oids[i])
        exit(1)

# Byte strings are:
# 0 - Salt (length 32)
# 1 - Partial IV (length 14, 2 bytes missing)
# 2 - AES ciphertext to decrypt
if len(bstrings) != 3:
    print('Expected 3 byte strings, got', len(bstrings))
    exit(1)
ct_salt = bstrings[0]
ct_short_iv = bstrings[1]
ct_aes = bstrings[2]

# Find the offset in ciphertext for the partial IV
if len(ct_short_iv) != 14:
    print('Expected 14 bytes partial IV')
    exit(1)
# There are two bytes missing
offset = ciphertext.find(ct_short_iv) - 2
if offset < 0:
    print('Failed to find IV in ciphertext')
    exit(1)
aes_iv = ciphertext[offset : offset + 16]

# ints should be [iterations, keylen]
if len(ints) != 2:
    print('Expected 2 integers, got', len(bstrings))
    exit(1)
iterations = ints[0] # Seems to always be 10000
keylen = ints[1]     # should be 32 for this algorithm

print('Decoded salt:')
hexdump(ct_salt)
print('Reconstructed IV')
hexdump(aes_iv)
print('Decoded AES ciphertext (still encrypted)')
hexdump(ct_aes)


# ^^^ Everything above this line is static
# The script should output the db_salt, ct_salt, aes_iv and aes_ct
# Then the rest can be looped in john.

unpad_cbc = lambda s: s[:-ord(s[len(s) - 1:])]

# Loop the lines below inside john later
# for each password candidate
print('')
pw = b'iloveyou'
saltpw = db_salt + pw
digest = hashlib.sha1(saltpw).digest()
print('sha1(salt + pw):')
hexdump(digest)
aes_key = hashlib.pbkdf2_hmac('sha256', digest, ct_salt, iterations)
print('AES key')
hexdump(aes_key)
cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
result = unpad_cbc(cipher.decrypt(ct_aes))
print(result)
print(result == b'password-check')
```

Fortunately, that hashcat commit from earlier told me the necessary parameters for formatting the hash in the format required by hashcat! Converting from the *Python extraction program output* to the *hashcat commit code variable names*:  
- `database salt` = `global_salt_bin`  
- `decoded salt` = `entry_salt_bin`  
- 10000 = `iter` (remember this was from looking at the hashcat hash mode examples database)  
- `reconstructed IV` = `iv_bin`  
- `decoded AES ciphertext` = `ct_bin`  

Formatting the hash into hashcat's desired format, we get:  
`$mozilla$*AES*3510a742f59b198e198922f0c9bc43cf8ab52bf3*dadd3df784b946b13619b7f09fdce2e7a34e3e0cd4069263a0517d683d003695*10000*040e6bb3481d3086ee025f5b4b5b0afb*9c55609a7548c032b1bee0a1d948cec5`  

Run `hashcat -a 0 -m 26100 hash ~/rockyou.txt` to get the master password of `phoenixthefirebird14`.  
Open up Firefox password manager, put in the master password, and get the decrypted password for picoctf.org!  

    flag{n0_p@ssw0rd_15_s3cur3??}