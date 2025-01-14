---
layout: writeup
category: Texsaw-CTF-2024
chall_description:
points: 50
solves: -1
tags: web web/headers
date: 2024-3-25
comments: false
---

We are at 3.23.56.243:9003. We are so secure that we only allow requests from our own origin to access secret data.  

---

Checking out the page request in Burp, we find this line in the response:  

```yaml
Access-Control-Allow-Origin: https://texsaw2024.com
```

So that's what our origin needs to be. Send the request to / to the Repeater and add in an Origin request header so that the request now looks like this:  

```yaml
GET / HTTP/1.1
Host: 3.23.56.243:9003
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
Origin: https://texsaw2024.com
```

And we get the flag!  

    texsaw{s7t_y0ur_or7g7n}