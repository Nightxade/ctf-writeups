---
layout: writeup
category: Texsaw-CTF-2024
chall_description:
points: 250
solves: -1
tags: web robots.txt error post
date: 2024-3-25
comments: false
---

The flag is at 3.23.56.243:9008. Unfortunately it seems like the site is down right now :( . Maybe you can ask someone for help? Don't blow up their inbox though :) and make sure you clearly tell them what you want.  

---

Visiting the [site](http://3.23.56.243:9008/), we are presented the following message, and nothing else:  

```
Website down! please contact IT for more information
```

Checking /robots.txt, we find some info:  

```
USER AGENTS: *
DISALLOW     contactIT
DISALLOW     countdown
```

Visiting /contactIT, we get this message:  

```
Post:Json Request Only
```

And /countdown returns some page with Pennywise in the background and the text "27 years."  

Heading into Burp Suite, we can send the request to /contactIT to the Repeater. Let's change the method to POST and resend the request:  

```yaml
POST /contactIT HTTP/1.1
Host: 3.23.56.243:9008
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
```

The response:  

```html
HTTP/1.1 415 UNSUPPORTED MEDIA TYPE
Server: Werkzeug/3.0.1 Python/3.12.2
Date: Sun, 24 Mar 2024 20:05:59 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 215
Connection: close

<!doctype html>
<html lang=en>
<title>415 Unsupported Media Type</title>
<h1>Unsupported Media Type</h1>
<p>Did not attempt to load JSON data because the request Content-Type was not &#39;application/json&#39;.</p>

```

Seems like we need to set the Content-Type header to "application/json". I also added some JSON into the data section to see if it'd produce a response:  

```yaml
POST /contactIT HTTP/1.1
Host: 3.23.56.243:9008
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 15
Content-Type: application/json

{"years": "27"}
```

The response:  

```html
HTTP/1.1 500 INTERNAL SERVER ERROR
Server: Werkzeug/3.0.1 Python/3.12.2
Date: Sun, 24 Mar 2024 20:10:40 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 15591
Connection: close

<!doctype html>
<html lang=en>
  <head>
    <title>TypeError: argument of type &#39;NoneType&#39; is not iterable
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = true,
          EVALEX_TRUSTED = false,
          SECRET = "WYleT8qx5TNo2HMQyp6Q";
    </script>
  </head>
  <body style="background-color: #fff">
    <div class="debugger">
<h1>TypeError</h1>
<div class="detail">
  <p class="errormsg">TypeError: argument of type &#39;NoneType&#39; is not iterable
</p>
</div>
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
<div class="traceback">
  <h3></h3>
  <ul><li><div class="frame" id="frame-140077653438480">
  <h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/app.py"</cite>,
      line <em class="line">1488</em>,
      in <code class="function">__call__</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">    </span>) -&gt; cabc.Iterable[bytes]:</pre>
<pre class="line before"><span class="ws">        </span>&#34;&#34;&#34;The WSGI server calls the Flask application object as the</pre>
<pre class="line before"><span class="ws">        </span>WSGI application. This calls :meth:`wsgi_app`, which can be</pre>
<pre class="line before"><span class="ws">        </span>wrapped to apply middleware.</pre>
<pre class="line before"><span class="ws">        </span>&#34;&#34;&#34;</pre>
<pre class="line current"><span class="ws">        </span>return self.wsgi_app(environ, start_response)
<span class="ws">        </span>       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^</pre></div>
</div>

<li><div class="frame" id="frame-140077653438624">
  <h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/app.py"</cite>,
      line <em class="line">1466</em>,
      in <code class="function">wsgi_app</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>try:</pre>
<pre class="line before"><span class="ws">                </span>ctx.push()</pre>
<pre class="line before"><span class="ws">                </span>response = self.full_dispatch_request()</pre>
<pre class="line before"><span class="ws">            </span>except Exception as e:</pre>
<pre class="line before"><span class="ws">                </span>error = e</pre>
<pre class="line current"><span class="ws">                </span>response = self.handle_exception(e)
<span class="ws">                </span>           ^^^^^^^^^^^^^^^^^^^^^^^^</pre>
<pre class="line after"><span class="ws">            </span>except:  # noqa: B001</pre>
<pre class="line after"><span class="ws">                </span>error = sys.exc_info()[1]</pre>
<pre class="line after"><span class="ws">                </span>raise</pre>
<pre class="line after"><span class="ws">            </span>return response(environ, start_response)</pre>
<pre class="line after"><span class="ws">        </span>finally:</pre></div>
</div>

<li><div class="frame" id="frame-140077653438768">
  <h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/app.py"</cite>,
      line <em class="line">1463</em>,
      in <code class="function">wsgi_app</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">        </span>ctx = self.request_context(environ)</pre>
<pre class="line before"><span class="ws">        </span>error: BaseException | None = None</pre>
<pre class="line before"><span class="ws">        </span>try:</pre>
<pre class="line before"><span class="ws">            </span>try:</pre>
<pre class="line before"><span class="ws">                </span>ctx.push()</pre>
<pre class="line current"><span class="ws">                </span>response = self.full_dispatch_request()
<span class="ws">                </span>           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^</pre>
<pre class="line after"><span class="ws">            </span>except Exception as e:</pre>
<pre class="line after"><span class="ws">                </span>error = e</pre>
<pre class="line after"><span class="ws">                </span>response = self.handle_exception(e)</pre>
<pre class="line after"><span class="ws">            </span>except:  # noqa: B001</pre>
<pre class="line after"><span class="ws">                </span>error = sys.exc_info()[1]</pre></div>
</div>

<li><div class="frame" id="frame-140077653438912">
  <h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/app.py"</cite>,
      line <em class="line">872</em>,
      in <code class="function">full_dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before"><span class="ws">            </span>rv = self.preprocess_request()</pre>
<pre class="line before"><span class="ws">            </span>if rv is None:</pre>
<pre class="line before"><span class="ws">                </span>rv = self.dispatch_request()</pre>
<pre class="line before"><span class="ws">        </span>except Exception as e:</pre>
<pre class="line current"><span class="ws">            </span>rv = self.handle_user_exception(e)
<span class="ws">            </span>     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^</pre>
<pre class="line after"><span class="ws">        </span>return self.finalize_request(rv)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def finalize_request(</pre>
<pre class="line after"><span class="ws">        </span>self,</pre>
<pre class="line after"><span class="ws">        </span>rv: ft.ResponseReturnValue | HTTPException,</pre></div>
</div>

<li><div class="frame" id="frame-140077653439056">
  <h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/app.py"</cite>,
      line <em class="line">870</em>,
      in <code class="function">full_dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws">        </span>try:</pre>
<pre class="line before"><span class="ws">            </span>request_started.send(self, _async_wrapper=self.ensure_sync)</pre>
<pre class="line before"><span class="ws">            </span>rv = self.preprocess_request()</pre>
<pre class="line before"><span class="ws">            </span>if rv is None:</pre>
<pre class="line current"><span class="ws">                </span>rv = self.dispatch_request()
<span class="ws">                </span>     ^^^^^^^^^^^^^^^^^^^^^^^</pre>
<pre class="line after"><span class="ws">        </span>except Exception as e:</pre>
<pre class="line after"><span class="ws">            </span>rv = self.handle_user_exception(e)</pre>
<pre class="line after"><span class="ws">        </span>return self.finalize_request(rv)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def finalize_request(</pre></div>
</div>

<li><div class="frame" id="frame-140077653439200">
  <h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/app.py"</cite>,
      line <em class="line">855</em>,
      in <code class="function">dispatch_request</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">            </span>and req.method == &#34;OPTIONS&#34;</pre>
<pre class="line before"><span class="ws">        </span>):</pre>
<pre class="line before"><span class="ws">            </span>return self.make_default_options_response()</pre>
<pre class="line before"><span class="ws">        </span># otherwise dispatch to the handler for that endpoint</pre>
<pre class="line before"><span class="ws">        </span>view_args: dict[str, t.Any] = req.view_args  # type: ignore[assignment]</pre>
<pre class="line current"><span class="ws">        </span>return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
<span class="ws">        </span>       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">    </span>def full_dispatch_request(self) -&gt; Response:</pre>
<pre class="line after"><span class="ws">        </span>&#34;&#34;&#34;Dispatches the request and on top of that performs request</pre>
<pre class="line after"><span class="ws">        </span>pre and postprocessing as well as HTTP exception catching and</pre>
<pre class="line after"><span class="ws">        </span>error handling.</pre></div>
</div>

<li><div class="frame" id="frame-140077653439344">
  <h4>File <cite class="filename">"/app/webapp.py"</cite>,
      line <em class="line">26</em>,
      in <code class="function">submitted</code></h4>
  <div class="source "><pre class="line before"><span class="ws">    </span>if request.method == &#39;POST&#39;:</pre>
<pre class="line before"><span class="ws">        </span>content = request.get_json()</pre>
<pre class="line before"><span class="ws">        </span>sender = content.get(&#39;email&#39;)</pre>
<pre class="line before"><span class="ws">        </span>messege = content.get(&#39;messege&#39;)</pre>
<pre class="line before"><span class="ws">        </span>f.setSender(sender)</pre>
<pre class="line current"><span class="ws">        </span>f.checkResponds(messege)
<span class="ws">        </span>^^^^^^^^^^^^^^^^^^^^^^^^</pre>
<pre class="line after"><span class="ws">    </span>else:</pre>
<pre class="line after"><span class="ws">        </span>return &#34;Post:Json Request Only&#34;</pre>
<pre class="line after"><span class="ws">    </span>return &#34;Email Sent!&#34;</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws"></span>@app.route(&#34;/countdown&#34;)</pre></div>
</div>

<li><div class="frame" id="frame-140077653439488">
  <h4>File <cite class="filename">"/app/floaty.py"</cite>,
      line <em class="line">17</em>,
      in <code class="function">checkResponds</code></h4>
  <div class="source "><pre class="line before"><span class="ws">    </span>def setSender(self, email):</pre>
<pre class="line before"><span class="ws">        </span>self.sendto = email</pre>
<pre class="line before"><span class="ws"></span> </pre>
<pre class="line before"><span class="ws"></span>#Check Responds for flag or fake</pre>
<pre class="line before"><span class="ws">    </span>def checkResponds(self, responds):</pre>
<pre class="line current"><span class="ws">        </span>if &#34;flag&#34; in responds:
<span class="ws">        </span>   ^^^^^^^^^^^^^^^^^^</pre>
<pre class="line after"><span class="ws">            </span>self.sendFlag()</pre>
<pre class="line after"><span class="ws">        </span>else:</pre>
<pre class="line after"><span class="ws">            </span>self.sendFake()</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws"></span>#Send Flag if requested</pre></div>
</div>
</ul>
  <blockquote>TypeError: argument of type &#39;NoneType&#39; is not iterable
</blockquote>
</div>

<div class="plain">
    <p>
      This is the Copy/Paste friendly version of the traceback.
    </p>
    <textarea cols="50" rows="10" name="code" readonly>Traceback (most recent call last):
  File &#34;/usr/local/lib/python3.12/site-packages/flask/app.py&#34;, line 1488, in __call__
    return self.wsgi_app(environ, start_response)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File &#34;/usr/local/lib/python3.12/site-packages/flask/app.py&#34;, line 1466, in wsgi_app
    response = self.handle_exception(e)
               ^^^^^^^^^^^^^^^^^^^^^^^^
  File &#34;/usr/local/lib/python3.12/site-packages/flask/app.py&#34;, line 1463, in wsgi_app
    response = self.full_dispatch_request()
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File &#34;/usr/local/lib/python3.12/site-packages/flask/app.py&#34;, line 872, in full_dispatch_request
    rv = self.handle_user_exception(e)
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File &#34;/usr/local/lib/python3.12/site-packages/flask/app.py&#34;, line 870, in full_dispatch_request
    rv = self.dispatch_request()
         ^^^^^^^^^^^^^^^^^^^^^^^
  File &#34;/usr/local/lib/python3.12/site-packages/flask/app.py&#34;, line 855, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File &#34;/app/webapp.py&#34;, line 26, in submitted
    f.checkResponds(messege)
  File &#34;/app/floaty.py&#34;, line 17, in checkResponds
    if &#34;flag&#34; in responds:
       ^^^^^^^^^^^^^^^^^^^
TypeError: argument of type &#39;NoneType&#39; is not iterable
</textarea>
</div>
<div class="explanation">
  The debugger caught an exception in your WSGI application.  You can now
  look at the traceback which led to the error.  <span class="nojavascript">
  If you enable JavaScript you can also use additional features such as code
  execution (if the evalex feature is enabled), automatic pasting of the
  exceptions and much more.</span>
</div>
      <div class="footer">
        Brought to you by <strong class="arthur">DON'T PANIC</strong>, your
        friendly Werkzeug powered traceback interpreter.
      </div>
    </div>

    <div class="pin-prompt">
      <div class="inner">
        <h3>Console Locked</h3>
        <p>
          The console is locked and needs to be unlocked by entering the PIN.
          You can find the PIN printed out on the standard output of your
          shell that runs the server.
        <form>
          <p>PIN:
            <input type=text name=pin size=14>
            <input type=submit name=btn value="Confirm Pin">
        </form>
      </div>
    </div>
  </body>
</html>

<!--

Traceback (most recent call last):
  File "/usr/local/lib/python3.12/site-packages/flask/app.py", line 1488, in __call__
    return self.wsgi_app(environ, start_response)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/flask/app.py", line 1466, in wsgi_app
    response = self.handle_exception(e)
               ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/flask/app.py", line 1463, in wsgi_app
    response = self.full_dispatch_request()
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/flask/app.py", line 872, in full_dispatch_request
    rv = self.handle_user_exception(e)
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/flask/app.py", line 870, in full_dispatch_request
    rv = self.dispatch_request()
         ^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/flask/app.py", line 855, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/app/webapp.py", line 26, in submitted
    f.checkResponds(messege)
  File "/app/floaty.py", line 17, in checkResponds
    if "flag" in responds:
       ^^^^^^^^^^^^^^^^^^^
TypeError: argument of type 'NoneType' is not iterable


-->
```

That's long...  

But, notably, after scrolling through, I noticed it seemed to be outputting the lines in the source code! Perfect. Let's try and write out what's going on, starting from line 139:  

This is /app/webapp.py:  

```py
def unknown_func():
    if request.method == "POST":
        content = request.get_json()
        sender = content.get("email")
        messege = content.get("messege")
        f.setSender(sender)
        f.checkResponds(messege)
    else:
        return "Post:Json Request Only"
    return "Email Sent!"

@app.route("/countdown")
```

And this is /app/floaty.py:  

```py
class unknown_class:
    def setSender(self, email):
        self.sendto = email

    #Check Responds for flag or fake
    def checkResponds(self, responds):
        if "flag" in responds:
            self.sendFlag()
        else:
            self.sendFake()
        #Send Flag if requested
```

Seems like we need to include a json object with an "email" and a "messege". The "email" should be one we can access, while the "messege" should just include the flag. Thus, the final request is as follows:  

```yaml
POST /contactIT HTTP/1.1
Host: 3.23.56.243:9008
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 66
Content-Type: application/json

{
    "email": "YOUREMAIL@email.com",
	"messege":   "flag"
}
```

The response:  

```html
HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.12.2
Date: Sun, 24 Mar 2024 20:16:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 11
Connection: close

Email Sent!
```

Check your email for the flag!  

    texsaw{7h15_15_7h3_r34l_fl46_c0n6r47ul4710n5}
