---
layout: ctf_overview
title: 1337UP LIVE CTF 2023
category: 1337UP-LIVE-CTF-2023
date: 2023-11-26
---

# Flag Extraction
## 50
They told me I just need to extract flag but I don't know what that means?!

---

After extracting the first file with an online .rar extractor, I realized that it was probably just a bunch of nested compressions/zips, given that the next file was a .tar.xz file.  
The easiest solutions are to either use 7-Zip File Manager or just "binwalk -eM" on Linux (-e means extract, -M is basically recursive), which results in a final file, flag.gif.  
Use a hex editor and Ctrl+F for "INTIGRITI" or do 'grep "INTIGRITI" flag.gif' on Linux to get the flag!  

    INTIGRITI{fl46_3x7r4c710n_c0mpl373}