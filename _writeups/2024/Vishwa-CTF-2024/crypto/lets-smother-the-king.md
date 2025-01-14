---
layout: writeup
category: Vishwa-CTF-2024
chall_description:
points: 300
solves: 79
tags: Vishwa-CTF-2024 crypto crypto/esoteric-language
date: 2024-3-3
comments: false
---

In my friend circle, Mr. Olmstead and Mr. Ben always communicate with each other through a secret code language that they created, which we never understand. Here is one of the messages Mr. Ben sent to Mr. Olmstead, which I somehow managed to hack and extract it from Ben's PC. However, it's encrypted, and I don't comprehend their programming language. Besides being proficient programmers, they are also professional chess players. It appears that this is a forced mate in a 4-move chess puzzle, but the information needs to be decrypted to solve it. Help me out here to solve the chess puzzle and get the flag.  

Flag format: VishwaCTF{move1ofWhite_move1ofBlack_move2ofWhite_move2ofBlack_move3ofWhite_move3ofBlack_move4ofWhite}.  

Note: Please use proper chess notations while writing any move.  

Author : Naman Chordia  

[code.txt](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Vishwa-CTF-2024/code.txt)  

---

Here's `code.txt`:  

    D'`A_9!7};|jE7TBRdQbqM(n&JlGGE3feB@!x=v<)\r8YXtsl2Sonmf,jLKa'edFEa`_X|?UTx;WPUTMqKPONGFjJ,HG@d'=BA@?>7[;4z21U54ts10/.'K+$j(!Efe#z@a}vut:[Zvutsrqj0ngOe+Lbg`edc\"CBXW{[TSRvP8TMq4JONGFj-IBGF?c=a$@9]=6|:3W10543,P*/.'&%$Hi'&%${z@a}vut:xqp6nVrqpoh.fedcb(IHdcba`_X|V[ZYXWPOsMLKJINGkKJI+G@dDCBA#"8=6Z4z21U5ut,P0)(-&J*)"!E}e#"!x>|uzs9qvo5srkpingf,Mchg`_%cbaZBXW{>=YXWPOs65KPImMLEDIBf)(D=a$:?>7<54X210/43,Pqp(',+*#G'gf|B"y?}v^tsr8vuWsrqpi/POkdibgf_%]b[Z_X|?>TYRQu8TMqQPIHGkEJIBA@dD&B;@?8\<5{3W70/.-Q10/on,%Ij('~}|B"!~}_u;y[Zponm3qpoQg-kjihgfeG]#aCBXW{[ZYX:Pt7SRQJONMLEiIHA@?cCB$@9]~<;:921U543,10/.-&J*j('~}${A!~}vuzs9Zponm3qpihmf,jihgfeG]#n

Searching 'olmstead cipher' returns [this](https://en.wikipedia.org/wiki/Malbolge). [This](https://malbolge.doleczek.pl/) interpreter gives the following output for the code:  

    White- Ke1,Qe5,Rc1,Rh1,Ne6,a2,b3,d2,f2,h2 Black- Ka8,Qh3,Rg8,Rh8,Bg7,a7,b7,e4,g2,g6,h7

Using a site like [this one](https://nextchessmove.com/) allows us to find the correct sequence of moves for the flag! (or solve it yourself - it's a simple smothered mate puzzle!)  

    VishwaCTF{Nc7+_Kb8_Na6+_Ka8_Qb8+_Rxb8_Nc7#}

### Thoughts
This is not really a crypto problem imo  