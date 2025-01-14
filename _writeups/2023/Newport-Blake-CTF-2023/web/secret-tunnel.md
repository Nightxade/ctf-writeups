---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/32n7io7.png
points: 264
solves: 148
tags: web web/localhost web/url-encoding
date: 2023-12-4
comments: false
---

Can you find the flag on the other end of my secret tunnel?  

[secret-tunnel.chal.nbctf.com](secret-tunnel.chal.nbctf.com)  

[secret_tunnel.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/web/secret-tunnel.zip)  

---

We're given a website and its source code, which helps us immediately realize we need to access `/flag.txt`. Now check out this section out from `main.py`:  

```py
if "127" in url:
    return Response("No loopback for you!", mimetype="text/plain")
if url.count('.') > 2:
    return Response("Only 2 dots allowed!", mimetype="text/plain")
if "x" in url:
    return Response("I don't like twitter >:(" , mimetype="text/plain") 
if "flag" in url:
    return Response("It's not gonna be that easy :)", mimetype="text/plain")
```

Seems like we need to pass some checks, first of all. 

Url-encoding actually allows us to pass all checks, as the link below allows us to access the flag link:  

    https://secret-tunnel%2Echal%2Enbctf.com/fla%67

Unfortunately, it doesn't show us the flag, only a little bit of the HTML.  

At this point, I turned back to the website's source code to look for clues. Two things stuck out to me.  

- The first check said something about a "loopback"...? Not sure what that is.  

- `flag.txt` is located on port 1337, but we didn't need to use that for our URL access. Why?  

I first looked up what a loopback was, with the query "loopback web ctf". This returned [this website](https://b1tsec.medium.com/advent-of-ctf-challenge-22-write-up-3da952b6513b), that talked about how a loopback essentially enabled local access?  

Well, let's try it out. The site also provides some info about a way to avoid filter checks for `127.0.0.1` with `0x7f000001`, but this triggered the third check, so we need to URL-encode that as well.  

    https://0%787f000001/fla%67

Here's what it returned:  

    HTTPSConnectionPool(host='0x7f000001', port=443): Max retries exceeded with url: /flag (Caused by NewConnectionError('<urllib3.connection.HTTPSConnection object at 0x7be950562500>: Failed to establish a new connection: [Errno 111] Connection refused'))

Huh. Seems like we're using the wrong port. Let's fix that:  

    https://0%787f000001:1337/fla%67

This is the response:  

    HTTPSConnectionPool(host='0x7f000001', port=1337): Max retries exceeded with url: /flag (Caused by SSLError(SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1007)')))

Hm. Still nothing. What's going wrong?  

Eventually, I just ended up Googling my error message to see what was going wrong. [This post](https://stackoverflow.com/questions/65516325/ssl-wrong-version-number-on-python-request) on stackoverflow told me exactly what I needed to know. We need to be using `http`, not `https`.  

Now we can construct a new payload:  

    http://0%787f000001:1337/fla%67

Which returns our flag!  

    nbctf{s3cr3t_7uNN3lllllllllll!}