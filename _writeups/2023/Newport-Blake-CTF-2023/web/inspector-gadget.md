---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/nQzGSIA.png
points: 100
solves: 266
tags: Newport-Blake-CTF-2023 web web/inspect
date: 2023-12-4
comments: false
---

While snooping around this website, inspector gadet lost parts of his flag. Can you help him find it?  

[inspector-gadget.chal.nbctf.com](inspector-gadget.chal.nbctf.com)  

---

The title is clearly implying we need to do some investigation with the Inspect function of Google Chrome.  

Going to `index.html` and using Ctrl+F for `_` returns part 3/4: `D3tect1v3_`  

Ctrl+F for 'flag' returns a `getflag()` function that has a `window.location.href` of `supersecrettopsecret.txt`. Checking out that file returns part 2/4: `J06_`  

Searching around some of the links, I finally got to the `Gadget Magnifying Glass` link, which had part 1/4 located in the `<title>` tag of the HTML: `nbctf{G00d_`  

Finally, I decided to visit `robots.txt`, to see if there was anything hidden there. Here was what I found:  

    User-agent: *
    Disallow: /mysecretfiles.html

Seems like something's hidden in `/mysecretfiles.html`! Visting that page gives us part 4/4, `G4dg3t352}`  

So our flag is:  

    nbctf{G00d_J06_D3tect1v3_G4dg3t352}