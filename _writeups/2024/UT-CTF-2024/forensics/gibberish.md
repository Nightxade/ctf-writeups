---
layout: writeup
category: UT-CTF-2024
chall_description:
points: 987
solves: 31
tags: UT-CTF-2024 forensics forensics/network forensics/stenography
date: 2024-4-1
comments: false
---

Help! I'm trying to spy on my lover but they're not typing in any language I'm familiar with!  

By mzone (@mzone on discord)  

Unlock Hint for 0 points  
I made this on a qwerty keyboard but I would recommend buying something more specialized if you were to do this all day. You'll know you're on the right track when you find something that rhymes with a word in the challenge description.  

Unlock Hint for 0 points  
It's not a cipher.  

Unlock Hint for 0 points  
I used a 6-key rollover keyboard. You might want to double check some of your words.  

[keyboard.pcapng](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/UT-CTF-2024/keyboard.pcapng)  

---

Check out the pcapng file. After a certain point, the packets just all become keybaord inputs. Notably, a 6-key rollover keyboard allows for up to 6 keys to be held at one time, which explains why some packets have 6 keys held simultaneously. Also, we are provided the hex values/corresponding code for each key.  

Using some tshark magic or a Python program on the packets (After exporting them), we can get to a file including only the coding for what keys were pressed at any given time. See [raw]().  

At this point, it took me a while before I was able to figure out what to do. I tried various different ways to print the packets, but nothing worked. Eventually, my team and I decided to reevaluate hint 1, after an admin confirmed hint 1 and 3 were not related (for some reason, I thought "rollover" was what they wanted to rhyme with "lover").  

The only word in the description that really seemed promising was "lover". I searched for words that rhyme with lover, and just started testing, searching up the word followed by "keyboard". Eventually, "plover" returned a [result](https://www.openstenoproject.org/plover/#get-started-with-plover).  

So it seemed like we were dealing stenography! That means all the key combinations that were ocurring in the network capture were stenography inputs into plover.  

As a result, I quickly maee a Pythoon program to output only the key combinations! i.e., notice how the data file for the key presses is almost like a sinusoidal wave and how it the keys are genereated -- the key combinations are the peaks of each wave.  

Here's the program to do this:  

```py
import keyboard

f = open('raw','r').read().split('\n')

d = dict()
for i in range(26):
    d["{:02x}".format(4 + i)] = chr(ord('a') + i)
d['2a'] = "backspace"
d['28'] = 'enter'
d['33'] = ';'
d['2c'] = 'space'
d['2f'] = '['
d['34'] = "'"
d['30'] = ']'

typed = []
deleted = []
nodel = []
for i in range(1, len(f) - 1):
    line = f[i]
    prev = f[i - 1]
    nex = f[i + 1]
    if line.count('0') < prev.count('0') and line.count('0') < nex.count('0'):
        s = []
        for j in range(0, len(line), 2):
            if line[j:j+2] == '00':
                break
            s.append(d[line[j:j+2]])
        if len(s) > 0:
            print("".join(s), end=' ')
```

Note that the "backspace", "enter", and "space" characteres were replaced with their corresponding word.  

Running the program results in:  

```yml
wcvnmi sdf backspace backspace backspace backspace dsgf wcvnmi enter cdl backspace ; rnj crl backspace backspace backspace backspace cr; cejp mrspacep backspace backspace backspace backspace backspace backspace emp ano backspace backspace backspace backspace backspace anp fvj backspace backspace backspace backspace backspace backspace dcj snip ajpv wvi niwa enj pvr pauv eapv wiva pcr pmrj oapc dnp nj;r pvej cwaj nkd dinp cj;d pmr pce backspace backspace backspace backspace backspace pve ifcw kvf i;ev backspace backspace backspace backspace backspace backspace wv;i pcro kem npe icjr fkm eamj pec akv fucp pvwf pcf cwi mlf amk ;cd nrj ;jcr backspace backspace backspace backspace backspace backspace backspace backspace ;cr pecj pme nap dcj inps apvj wiv nawi nje vpr aivp backspace backspace backspace backspace backspace backspace aupv epva wvoa backspace backspace backspace backspace backspace backspace backspace backspace wavi pcr rmpj caop pdn ;njrspace pejv wcaj ndk ind backspace backspace backspace backspace backspace backspace backspace backspace backspace dnip scj; backspace backspace backspace backspace backspace backspace cdj; mrp cep backspace backspace backspace backspace backspace backspace evp cwif fvkj backspace backspace backspace backspace wvfi; backspace backspace backspace backspace backspace backspace backspace backspace backspace wvf backspace backspace backspace backspace backspace wvi; crop mke enp crji mfk eamj ceo backspace backspace backspace backspace ce[p backspace backspace backspace backspace avk pcuf pvfwj backspace wpvf pfc iwc lfm amk ;dc njr lcr backspace backspace backspace backspace backspace ;cr cpej pme anp dcf backspace backspace backspace backspace backspace cdj npis ajvp wvi anwjispace backspace wnaij backspace backspace backspace backspace backspace backspace backspace backspace wani enj vrp wervnp ecg[ enter fn ercvnm nmujk nmuj[ backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace fn ecvrmn mn[ backspace backspace backspace backspace backspace backspace backspace backspace fn ervcmn mnik[ hnj awer ruipo space anp wercfl wv mp wecrfl weflkp rfnjik njikl fgikm[ awervl wenm fgikm[ vik fgikm[ cnm fgikm[ sdjnp sdfnm fgmik[ svcnk[ fgmik[ a fgikm[ sdvcnm backspace backspace backspace backspace sdvcnm nmp fgmik[ wsmn mnuop[ wefgk efgkl klp space ecrnm nmkl arjm wv fn evru wernm aecnm; ; s cd; rnj a[n rclk backspace backspace backspace backspace backspace cr; dno cejp j[dvo nr rn[ pem own cprj npa wov[ svj; [vjd dv[j' backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace ['vdj [jdv v'dr cru a'n [nspacer [nro dcj spnji backspace backspace backspace backspace backspace backspace snip rc[j vro[ av[j backspace backspace backspace backspace backspace backspace backspace avjp spm ;ce vjr ; backspace backspace backspace backspace backspace ;vjr [njf backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace [nfj backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace ]jnf backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace backspace [nf p;vjr backspace backspace backspace backspace backspace backspace backspace backspace p;jce pvjs iwv wnai nje prv anwi backspace o backspace backspace backspace backspace backspace backspace backspace backspace nwiaj backspace backspace backspace backspace backspace backspace backspace backspace backspace wian; apuv eva evpa awvo backspace backspace backspace backspace backspace backspace awvo backspace backspace backspace backspace backspace backspace backspace awvi
```

At this point, I actually ended up using plover to type this all out by hand... unfortunately, I didn't quite end up with the right thing. Note that I replaced backspace, space, and enter with their actual keys:  

```yml
 type y type
 was her has par put se war kept sort top step per hot soft spot stop hat hurt salt wet hers port star web wept  wars hu pot trap ro tops halt pub pet harp rub spur pat sob raft  trot rat top rug sub was he has part put set war kept sort top step per ho soft sp stop hat  hurt salt wet  hers port star w wep wars h pot tra tops halt pub pet harp  rub spur pa sob raft transpor trot rat tap  rug sub was he has part put se war kept sort top  ST step per hot notepad
 remy i has well part world he head put tell heart set told ker kept hard hol sort cut pass ho  pats court top step per steps soft SPO spo stop
```

I'm not actually sure why this didn't end up revealing something to me. Either I typed it wrong or perhaps the backspace actually removed the flag :(  

Regardless, I ended up asking the admin for a sanity check on these words, because I felt like there was no way it was correct. However, he ended up hinting towards "type y type" being, not necessarily helpful, but possibly able to clarify things.  

Searching it up results in [this](https://didoesdigital.com/typey-type/) stenography practice site. I ended up just trying the introduction after looking around, and look at the first words:  

```yml
was​ her has part put set war kept sort top step per hot soft spot stop hat hurt salt wet hers port
```

Seems oddly similar to what I got... I guessed that somehow the backspaces I was doing messed up the words, and that without them, I would get the right sequence!  

However, after this, I was still a bit stuck. I still wasn't sure how to find the flag. I attempted to look at what was in the introduction but missing from my text, but to no avail.  

Eventually, I ended up just using plover to test out random key combinations. I eventually ended up stumbling upon this:  

`mp wecrfl weflkp`  

Which, when stenography-encoded, turned into `utflag{`.  

I was pretty ecstatic when I Found this, as I had already spent about 4 hours on this challenge alone. I quickly translated the rest of the words, sometimes with the help of [this site](https://didoesdigital.com/typey-type/writer), but it ended up turning out like this:  

`utflag{learn earning_stenography_on_a_qwerty_keyboard_is_quae it_Deisted TPR*B PR*BG`  

That's not quite right...

I assumed learn + earning was meant to be learning, but what aboute the rest?  

Well, I ended up finding [this site](https://sites.google.com/site/ploverdoc/appendix-cheat-sheet), which told me that "TPR*BG" encoded to "}".  

At this point, I realized that certain key combinations were supposed to combine together. I noticed this earlier when stenography was created rather weirdly, but I now realized that some of the combinations were not working.  

The challenge author later told me, after I solved the problem, that hint 3 was the key to resolving this issue. Because the user has a 6-key rollover keyboard, they cannot type more than that, meaning some words which require more than 6 keys to be simultaneously pressed to produce the correct result were split up into two sections For example, "sdvcnm nmp" was the user trying to type "sdvcnmp". The intended solution was thus to, in plover, do File -> Configure -> Machine -> Arpeggiate. This would allow the user to add any number of keys to a certain stenography combination, and then press space to send it, allowing 6-key rollover keyboards to use more than 6 keys in a single combination.  

However, I didn't realize this. Instead, I spent the next 20 minutes trying to figure out "quae it" and "Deisted".  

I ended up returning to [this site](https://didoesdigital.com/typey-type/writer). Here, I first tried the combinations for "quae it", i.e. "sdvcnm" and "nmp", by entering them in the text box for "QWERTY steno input". Through this, I realized that the corresponding stenography keys somewhat aligned up a bit (displayed in the stenography keybaord on the site). "sdvcnm" was KWAOEU and "nmp" was EUT. Hence, I guessed that perhaps combining them would produce the right word. Turns out, I was right! KAWOEUT returns "quite"!  

I thought I was done with the problem now, but "Deisted" produced more problems for me. Its QWERTY steno combinations were "wsmn" and "mnuop[a". These produced "TKEU" and "EUFLTD". However, combining these resulted in just TKEUFLTD, i.e., it was not translating to a specific word. I ended up being stuck here for a bit, not sure how to proceed. Eventually, I returned to [this site](https://sites.google.com/site/ploverdoc/appendix-cheat-sheet), which informed me that TK was equivalent to the letter "d" and EU was equivalent to the letter "i", accoding to [this](https://docs.google.com/file/d/1Yi93aHaxe3L-_ePtq3bujv7o1CCLmmgim8iuL_Sx2IY/edit),  

However, it seemed like F, L, T, and D had no connections with each other...  

But the site also said this: `If the sounds for a word can fit into steno order, then you can type that word with one stroke:`.  

This seemed interesting, but I wasn't sure how "di" + "FLTD" translated to anything. I spent another 10 minutes trying to think of what word could fit here, and, eventually I realized that it was probably "difficult", as it made perfect sense in the context!  

So, after, no joke, 5 hours of working on this problem, I finally got the flag:  

    utflag{learning_stenography_on_a_qwerty_keyboard_is_quite_difficult}