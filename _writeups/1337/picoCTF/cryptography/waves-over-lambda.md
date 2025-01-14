---
layout: writeup
category: picoCTF
chall_description: https://i.imgur.com/Qvc9ko7.png
points: 300
solves: 3349
tags: picoCTF crypto crypto/monoalphabetic-substitution
date: 1337-01-01
comments: false
---

We made a lot of substitutions to encrypt this. Can you decrypt it? Connect with `nc jupiter.challenges.picoctf.org 13758`.  

---

Connecting to the service, we get the following string:  
```
-------------------------------------------------------------------------------
zsxoimvr wlil nr jsci qumo - qilkclxzj_nr_z_seli_umtbfm_fxevqivmjc
-------------------------------------------------------------------------------
blvallx cr vwlil amr, mr n wmel muilmfj rmnf rstlawlil, vwl bsxf sq vwl rlm. blrnflr wsufnxo sci wlmivr vsolvwli vwiscow usxo glinsfr sq rlgmimvnsx, nv wmf vwl lqqlzv sq tmhnxo cr vsulimxv sq lmzw svwli'r jmixrmxf lelx zsxenzvnsxr. vwl umajlivwl blrv sq suf qluusarwmf, blzmcrl sq wnr tmxj jlmir mxf tmxj enivclr, vwl sxuj zcrwnsx sx flzh, mxf amr ujnxo sx vwl sxuj ico. vwl mzzscxvmxv wmf biscowv scv muilmfj m bsd sq fstnxslr, mxf amr vsjnxo mizwnvlzvcimuuj anvw vwl bsxlr. tmiusa rmv zisrr-uloolf inowv mqv, ulmxnxo momnxrv vwl tnyylx-tmrv. wl wmf rcxhlx zwllhr, m jluusa zstguldnsx, m rvimnowv bmzh, mx mrzlvnz mrglzv, mxf, anvw wnr mitr fisgglf, vwl gmutr sq wmxfr scvamifr, ilrltbulf mx nfsu. vwl fnilzvsi, rmvnrqnlf vwl mxzwsi wmf ossf wsuf, tmfl wnr amj mqv mxf rmv fsax mtsxorv cr. al ldzwmxolf m qla asifr umynuj. mqvliamifr vwlil amr rnulxzl sx bsmif vwl jmzwv. qsi rstl ilmrsx si svwli al fnf xsv blonx vwmv omtl sq fstnxslr. al qluv tlfnvmvnel, mxf qnv qsi xsvwnxo bcv gumznf rvminxo. vwl fmj amr lxfnxo nx m rlilxnvj sq rvnuu mxf ldkcnrnvl binuunmxzl. vwl amvli rwsxl gmznqnzmuuj; vwl rhj, anvwscv m rglzh, amr m blxnox nttlxrnvj sq cxrvmnxlf unowv; vwl elij tnrv sx vwl lrrld tmirw amr unhl m omcyj mxf imfnmxv qmbinz, wcxo qist vwl assflf inrlr nxumxf, mxf fimgnxo vwl usa rwsilr nx fnmgwmxscr qsufr. sxuj vwl ousst vs vwl alrv, bissfnxo seli vwl cggli ilmzwlr, blzmtl tsil rstbil lelij tnxcvl, mr nq mxolilf bj vwl mggismzw sq vwl rcx.
```

The problem description explains that a lot of substitutions were made. Let’s plug it into a letter frequency analysis [solver](https://www.guballa.de/substitution-solver). You should receive your flag:  

    picoCTF{frequency_is_c_over_lambda_dnvtfrtayu}

