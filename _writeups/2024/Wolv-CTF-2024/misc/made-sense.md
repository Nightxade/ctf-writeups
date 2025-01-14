---
layout: writeup
category: Wolv-CTF-2024
chall_description:
points: 100
solves: 250
tags: misc misc/jail misc/makefile
date: 2024-3-19
comments: false
---

i couldn't log in to my server so my friend kindly spun up a server to let me test makefiles. at least, they thought i couldn't log in :P  

[https://madesense-okntin33tq-ul.a.run.app](https://madesense-okntin33tq-ul.a.run.app)  

---

Visiting the website brings us to a page where we can enter a "Target name" and something into a text box and click "make". We are also linked to a source file:  

```py

import os
from pathlib import Path
import re
import subprocess
import tempfile

from flask import Flask, request, send_file

app = Flask(__name__)
flag = open('flag.txt').read()


def write_flag(path):
    with open(path / 'flag.txt', 'w') as f:
        f.write(flag)


def generate_makefile(name, content, path):
    with open(path / 'Makefile', 'w') as f:
        f.write(f"""
SHELL := /bin/bash
.PHONY: {name}
{name}: flag.txt
\t{content}
""")


@app.route('/', methods=['GET'])
def index():
    return send_file('index.html')


@app.route('/src/', methods=['GET'])
def src():
    return send_file(__file__)


# made sense
@app.route('/make', methods=['POST'])
def make():
    target_name = request.form.get('name')
    code = request.form.get('code')

    print(code)
    if not re.fullmatch(r'[A-Za-z0-9]+', target_name):
        return 'no'
    if '\n' in code:
        return 'no'
    if re.search(r'flag', code):
        return 'no'

    with tempfile.TemporaryDirectory() as dir:
        run_dir = Path(dir)
        write_flag(run_dir)
        generate_makefile(target_name, code, run_dir)
        sp = subprocess.run(['make'], capture_output=True, cwd=run_dir)
        return f"""
<h1>stdout:</h1>
{sp.stdout}
<h1>stderr:</h1>
{sp.stderr}
    """


app.run('localhost', 8000)
```

These are the checks being run on our Makefile code:  

```py
if not re.fullmatch(r'[A-Za-z0-9]+', target_name):
    return 'no'
if '\n' in code:
    return 'no'
if re.search(r'flag', code):
    return 'no'
```

So alphanumeric only for the name, one line, and not allowed to include "flag".  

I've never used a Makefile before, so I did a little bit of research on it. I quickly realized it just executed shell commands, so I figured I could probably just do some bash magic to print the flag. I put the "Target name" as something random and then put `cat fl*` into the text box.  

Clicked make and got the flag!  

    wctf{m4k1ng_vuln3r4b1l1t135}