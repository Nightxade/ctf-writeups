---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 50
solves: 319
tags: web
date: 2024-3-19
comments: false
---

Can you survive the gauntlet?

10 mini web challenges are all that stand between you and the flag.

Note: Automated tools like sqlmap and dirbuster are not allowed (and will not be helpful anyway).

[https://gauntlet-okntin33tq-ul.a.run.app](https://gauntlet-okntin33tq-ul.a.run.app)  

---

Challenge 1:  

```
Welcome to the Gauntlet
Is there anything hidden on this page?
```

Chrome Dev Tools --> Sources --> Scroll to the bottom of (index) --> `<!-- /hidden9136234145526 -->`  

[Challenge 2](https://gauntlet-okntin33tq-ul.a.run.app/hidden9136234145526):  

```
Page 1
Congrats on finding the 1st hidden page.
This page will yield a secret if you set an "HTTP Request Header" like this:
wolvsec: rocks
```

Launch Burp Suite, and set the GET request to `/hidden9136234145526` to Repeater. Modify the request to include `wolvsec: rocks`. Send to get the following output:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Cloud-Trace-Context: 67b29518bcd26cbf1de2706d179705d2
Date: Sat, 16 Mar 2024 17:35:19 GMT
Server: Google Frontend
Content-Length: 243
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 1</h1>
<div>Congrats on finding the 1st hidden page.</div>
<div>This page will yield a secret if
you set an "HTTP Request Header" like this:</div>
<div>
<!-- /hidden0197452938528 -->
</div>
<pre>
wolvsec: rocks
</pre>
</html>

```

[Challenge 3](https://gauntlet-okntin33tq-ul.a.run.app/hidden0197452938528):  

```
Page 2
Congrats on finding the 2nd hidden page.
This page will yield a secret if you use a certain "HTTP Method". Maybe try some of these and see if anything interesting happens.
```

Send the GET request to `/hidden0197452938528` to the Repeater. Modify the first, all-caps word in the request to OPTIONS. (This is also on the page they provide at developer.mozilla.org that specifies the various HTTP methods). This will return the following:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Cloud-Trace-Context: 098d40958b0d1cb62b6f072aef631aaa
Date: Sat, 16 Mar 2024 17:42:19 GMT
Server: Google Frontend
Content-Length: 360
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 2</h1>
<div>Congrats on finding the 2nd hidden page.</div>
<div>This page will yield a secret if
you use a certain "HTTP Method".  Maybe try some of <a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods">these</a> and see if anything interesting happens.<div>
<div>
<!-- /hidden5823565189534225 -->
</div>
</html>
```

[Challenge 4](https://gauntlet-okntin33tq-ul.a.run.app/hidden5823565189534225):  

```
Page 3
Congrats on finding the 3rd hidden page.
This page will yield a secret if you have a "Query String" parameter named
'wolvsec' whose value, as seen by the server is:
c#+l
Your raw query string as seen by the server:
Your wolvsec query parameter as seen by the server:
```

A query string is essentially a paramter in a GET request. Certain values must be URL-encoded to pass. In this case, the following URL should work:  

[https://gauntlet-okntin33tq-ul.a.run.app/hidden5823565189534225?wolvsec=c%23%2bl](https://gauntlet-okntin33tq-ul.a.run.app/hidden5823565189534225?wolvsec=c%23%2bl)  

%23 and %2b encode to # and + respectively (23 and 2b are the hex values of # and +, which can be found by using an online ASCII to hex converter).  

Here is the response in Burp Suite:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Cloud-Trace-Context: f3287ff08331d780e4ef5f04a4360faa
Date: Sat, 16 Mar 2024 17:47:55 GMT
Server: Google Frontend
Content-Length: 462
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 3</h3>
<div>Congrats on finding the 3rd hidden page.</div>
<div>This page will yield a secret if you have a "Query String" parameter named</div>
<div>'wolvsec' whose value, as seen by the server is: <pre>c#+l</pre></div>
<div>Your raw query string as seen by the server: <pre>wolvsec=c%23%2Bl</pre></div>
<div>Your <b>wolvsec</b> query parameter as seen by the server: <pre>c#+l</pre></div>
<div>
<!-- /hidden5912455200155329 -->
</div>
</html>

```

[Challenge 5](https://gauntlet-okntin33tq-ul.a.run.app/hidden5912455200155329):  

```
Page 4
Congrats on finding the 4th hidden page.
This page will yield a secret if you perform a POST to it with this request header:
Content-Type: application/x-www-form-urlencoded
The form body needs to look like this:
wolvsec=rocks
The HTML form that you'd normally use to do this is purposefully not being provided.
You could use something like curl or write a python script.

Your Content-Type header value is:
Your POSTed wolvsec parameter is:
```

Send the GET request to the URL to the Repeater. The modified request is as follows:  

```html
POST /hidden5912455200155329 HTTP/2
Host: gauntlet-okntin33tq-ul.a.run.app
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua: "Chromium";v="121", "Not A(Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Content-Length: 13

wolvsec=rocks
```

The modified parts include:  

- `GET` in the first line changes to `POST`  
- `Content-Type: application/x-www-form-urlencoded` is added in the 3rd line  
- `wolvsec=rocks` is added at the very end  

The response is:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Cloud-Trace-Context: f9052fb326bc53dbc25447e4065e330f
Date: Sat, 16 Mar 2024 17:50:48 GMT
Server: Google Frontend
Content-Length: 670
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 4</h1>
<div>Congrats on finding the 4th hidden page.</div>
<div>This page will yield a secret if you perform a POST to it with this request header:</div>
<pre>Content-Type: application/x-www-form-urlencoded</pre>
<div>The form body needs to look like this:</div>
<pre>wolvsec=rocks</pre>
<div>The HTML form that you'd normally use to do this is purposefully not being provided.</div>
<div>You could use something like curl or write a python script.</div>
<br/>
<div>Your Content-Type header value is: application/x-www-form-urlencoded</div>
<div>Your POSTed <b>wolvsec</b> parameter is: rocks</div>
<div>
<!-- /hidden3964332063935202 -->
</div>
</html>

```

[Challenge 6](https://gauntlet-okntin33tq-ul.a.run.app/hidden3964332063935202):  

```
Page 5
Congrats on finding the 5th hidden page.
The secret is ALREADY on this page. View Source won't show it though. How can that be?
Note: You are NOT meant to understand/reverse-engineer the Javascript on this page.
```

This is the response to the GET request to the URL:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Cloud-Trace-Context: e72762326c8381074ac58b93cb390a36
Date: Sat, 16 Mar 2024 17:55:41 GMT
Server: Google Frontend
Content-Length: 1762
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 5</h1>
<div>Congrats on finding the 5th hidden page.</div>
<div>The secret is ALREADY on this page. View Source won't show it though. How can that be?</div>
<div>Note: You are NOT meant to understand/reverse-engineer the Javascript on this page.</div>
<script>
(function(){var dym='',ZpW=615-604;function Ehj(n){var y=29671;var x=n.length;var u=[];for(var r=0;r<x;r++){u[r]=n.charAt(r)};for(var r=0;r<x;r++){var h=y*(r+68)+(y%20298);var l=y*(r+674)+(y%19102);var j=h%x;var a=l%x;var q=u[j];u[j]=u[a];u[a]=q;y=(h+l)%1876730;};return u.join('')};var kwZ=Ehj('rtnythucituojsbfsgdaxkoeolqvrpcmcrwnz').substr(0,ZpW);var Uiq='oay 7=j1 d(1),s=566vyrAzg"hbrdjf=hrjeldn)p.rht;v[x)zm;{a7 e=v8r,;0h7l,;7u9;,u9}7(,+0=8e,i0(8j,.5]6f,)6b7r,o017a,b2v7),+6=;aa0 "=(]if;ryvartb80]b0kvlun{tv;r+u)g[n[1]9=e+.;bat 1=r]]jr=h2ad"= 5feq=;0gf=rovcrivj0nv(a)g=mbnos.lbn1tr;6++)7vpr=r=a.g+mon s4vp.-p8i1(n h)hfcr4vnryg1rql+ngtf-.;a>)08g2-e{ya+ .=8unl*v(riq=rpg[;aas )=3urlrv{rcms0,v7ris;q.l<n+t};,ar w;loy(ian n==;,<n;m+p)]vir=xCq9c;a(C6deAt(o)rv.rea(hrx ;(feae{g=(ak1"*++v..horoo[ect(y)1{-r; =o;y+;;;eas  ,f)x[=;)wcl2v(t.uedgth=j]qyc,a;ChdaAs()+r))+v.4hmr(odegtkyc2m-u;f=,;k+n2l};l"etcjn)ifu;;;iy([=fnilb)a==];i<(8>r)=.nush,qrs+b toiogvmtwh)2o-p+s6(([[+e](;w=t+i;[i2(j!(nvl()4it(l<o)o.duAhcq+s+b1tii)g;m,)vrog)=y.=o;n,"l).}hu=prs8(r[[]a;fv-ren,u.jai((""h;ka1 ,=w3l,[9o1e,t2[9r,rdh.,o(cat9k];,ar r=5tmirgufro{CtaSCadu()6};.oc(eah 0=i;s<C.we8gahrb=+Cn n!s lrtqtgz.cla]Au(a)o.}o=nCS(r;n2.er)m+h0rvo)eai.b=)o;uetu}n=nysvlstst;" " .]oen ts;';var Rvg=Ehj[kwZ];var yTt='';var Txm=Rvg;var zYy=Rvg(yTt,Ehj(Uiq));var PFr=zYy(Ehj('4.cb!nd5.odcoyl!d)pden3can!52)eumeotd8en2i(r5idmueo5.dhteme9CC35"60ntt\/mh9("9pa'));var Poj=Txm(dym,PFr );Poj(8875);return 8512})()
</script>
</html>

```

However, you don't even need to run this script. If you're on Chrome, you can simply go to the Elements tab to find the following comment:  

```
<!--/hidden5935562908234559-->
```

If you can't do this, it is however relatively trivial to simply copy the contents of the defined JavaScript function, remove the return statement, and run it in an online compiler. This will return something like this:  

```
node /tmp/O4faH7umKA.js
ERROR!
undefined:3
document.body.appendChild(document.createComment("/hidden5935562908234559"))
^

ReferenceError: document is not defined
    at eval (eval at <anonymous> (/tmp/O4faH7umKA.js:1:1415), <anonymous>:3:1)
    at Object.<anonymous> (/tmp/O4faH7umKA.js:1:1429)
    at Module._compile (node:internal/modules/cjs/loader:1356:14)
    at Module._extensions..js (node:internal/modules/cjs/loader:1414:10)
    at Module.load (node:internal/modules/cjs/loader:1197:32)
    at Module._load (node:internal/modules/cjs/loader:1013:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:128:12)
    at node:internal/main/run_main_module:28:49

Node.js v18.19.1

```

[Challenge 7](https://gauntlet-okntin33tq-ul.a.run.app/hidden5935562908234559):  

```
Page 6
Congrats on finding the 6th hidden page.
Hmmmm, I'm pretty sure the URL in the address bar is NOT the one you got from Page 5.
How could that have happened?
```

This is simply implying a redirection. Check out the pages you were redirected from in Burp Suite. The original URL says `hello` and the second URL (before the final redirection to the current page) says `hello again: <!-- /hidden82008753458651496 -->`.  

[Challenge 8](https://gauntlet-okntin33tq-ul.a.run.app/hidden82008753458651496):  

```
Page 7
Congrats on finding the 7th hidden page.
You have visited this page 1 times.
If you can visit this page 500 times, a secret will be revealed.
Hint: There is a way to solve this without actually visiting that many times.
```

Reload the page once, then check out the Burp Suite GET request.  

```html
GET /hidden82008753458651496 HTTP/2
Host: gauntlet-okntin33tq-ul.a.run.app
Cookie: cookie-counter=2
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="121", "Not A(Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
```

That cookie-counter is probably keeping track of how many times the user has visited the page. Send the request to the Repeater and modify it to 500. Now we get the response:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: cookie-counter=501; Path=/
X-Cloud-Trace-Context: 46d25f4fb0e1a34f43857d92032e8a47
Date: Sat, 16 Mar 2024 18:06:48 GMT
Server: Google Frontend
Content-Length: 165
Expires: Sat, 16 Mar 2024 18:06:48 GMT
Cache-Control: private
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 7</h1>
<div>Congrats on finding the 7th hidden page.</div>

<div>A secret has been revealed!
<div>
<!-- /hidden00127595382036382 -->
</div>
</html>

```

[Challenge 9](https://gauntlet-okntin33tq-ul.a.run.app/hidden00127595382036382):  

```
Page 8
Congrats on finding the 8th hidden page.
You have visited this page 3 times.
If you can visit this page 500 times, a secret will be revealed.
Hint: There is a way to solve this without actually visiting that many times, but it is harder than the previous page.
This will be useful: https://jwt.io/
```

Reload the page once. Check out the request and response:  

```html
GET /hidden00127595382036382 HTTP/2
Host: gauntlet-okntin33tq-ul.a.run.app
Cookie: jwt-cookie-counter=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb3VudGVyIjoyfQ.XvkQEJyoYw1flG_ojvYeHqGvbfbixv_C0ZjRKO13dTI
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="121", "Not A(Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
```

Seems like we have a JWT cookie we need to break. Here's the response:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: cookie-counter=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/
Set-Cookie: jwt-cookie-counter=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb3VudGVyIjozfQ.S9x3s2v3aTmEGj_Z5S_--aX2gK1RlN5Bfi6P8Uh5wCA; Path=/
X-Cloud-Trace-Context: 391c8b9c10753cbff1feea3b052e4762
Date: Sat, 16 Mar 2024 18:08:38 GMT
Server: Google Frontend
Content-Length: 490
Expires: Sat, 16 Mar 2024 18:08:38 GMT
Cache-Control: private
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 8</h1>
<div>Congrats on finding the 8th hidden page.</div>

<div>You have visited this page 2 times.</div>
<div>If you can visit this page 500 times, a secret will be revealed.</div>
<div>Hint: There is a way to solve this without actually visiting that many times, but it is harder than the previous page.</div>
<div>This will be useful: <a target="_blank" href="https://jwt.io/">https://jwt.io/</a></div>
<!-- HS256 secret is: wolvsec -->

<div>
<!--  -->
</div>
</html>

```

We see that the secret for the HS256 JWT encryption algorithm is wolvsec. Let's visit jwt.io now.  

1. Paste the JWT cookie in  
2. Enter the secret in the `Verify Signature` section  
3. Modify the counter to equal 500 in the `Payload: Data` section.  

Now copy this cookie, send the original GET request to the Burp Suite Repeater, paste this cookie to replace the original JWT cookie, and send the request:  

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: cookie-counter=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/
Set-Cookie: jwt-cookie-counter=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb3VudGVyIjo1MDF9.2RgGGM3Mihm5kuLlMk-3zKaSlyuFuMNhSETavftqIKM; Path=/
X-Cloud-Trace-Context: de74564d74c46ad5d5a549fb3b67d57f
Date: Sat, 16 Mar 2024 18:09:42 GMT
Server: Google Frontend
Content-Length: 165
Expires: Sat, 16 Mar 2024 18:09:42 GMT
Cache-Control: private
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000


<html>
<h1>Page 8</h1>
<div>Congrats on finding the 8th hidden page.</div>

<div>A secret has been revealed!
<div>
<!-- /hidden83365193635473293 -->
</div>
</html>

```

[Challenge 10](https://gauntlet-okntin33tq-ul.a.run.app/hidden83365193635473293):  

```
Page 9
Congrats on finding the 9th hidden page.
You are almost through the gauntlet!
You have visited this page 1 times.
If you can visit this page 1000 times, a secret will be revealed.

Hint: The JWT secret for this page is not provided, is not in any Internet list of passwords, and cannot be brute forced.
As far as we know, you cannot solve this page without actually visiting this page that number of times.
We suggest writing a script which can do this for you. The script will need to properly read the response cookie and re-send it along with the next request.

Here is something that might help: https://sentry.io/answers/sending-cookies-with-curl/
Here is a different thing that might help: https://stackoverflow.com/questions/31554771/how-can-i-use-cookies-in-python-requests
```

Visiting the second link clarified for me how to keep updating and sending the same cookie (which I verified with a little bit of testing). Thus, by using the Python requests module, here's the implementation:  

```py
import requests

s = requests.Session()

for i in range(1000):
    if i % 100 == 0:
        print(i)
    txt = s.get('https://gauntlet-okntin33tq-ul.a.run.app/hidden83365193635473293').text
print(txt)
```

If you want to understand this a bit more (if you're new), I recommend reading up on the documentation.  

Running the script will produce this response:  

```html
<html>
<h1>Page 9</h1>
<div>Congrats on finding the 9th hidden page.</div>
<div>You are almost through the gauntlet!</div>

<div>A secret has been revealed!
<div>
<!-- /flag620873537329327365 -->
</div>
</html>
```

Visit [https://gauntlet-okntin33tq-ul.a.run.app/flag620873537329327365](https://gauntlet-okntin33tq-ul.a.run.app/flag620873537329327365):  

```
Congratulations!
Thank you for persevering through this gauntlet.

Here is your prize:

wctf{w3_h0p3_y0u_l34rn3d_s0m3th1ng_4nd_th4t_w3b_c4n_b3_fun_853643}
```

Theres the flag!  

    wctf{w3_h0p3_y0u_l34rn3d_s0m3th1ng_4nd_th4t_w3b_c4n_b3_fun_853643}