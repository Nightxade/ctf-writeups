---
layout: writeup
category: BCA-CTF-2024
chall_description:
points: 175
solves: 16
tags: crypto sha256 length-extension-attack
date: 2024-06-12
comments: false
---

Cinnamon Dynamics, an innovative technology company, provides a service for the public to execute short scripts to query some limited information about the company. To combat abuse, they've instated a requirement for all scripts to be approved by a company employee before they can be executed. Approved scripts are granted a "script token" that allows them to be executed an indefinite amount of times, so long as the script is not modified. Unfortunately, it seems that malicious actors have managed to circumvent the security system...

[challs.bcactf.com:31077](challs.bcactf.com:31077)  

[server.js](https://github.com/Nightxade/ctf-writeups/tree/master/assets/CTFs/BCA-CTF-2024/cinn_server.js)  

---

Here's the JavaScript source file:  

```js
import { createHash, timingSafeEqual } from 'crypto'
import { spawn } from 'child_process'
import { readFileSync } from 'fs'
import { join } from 'path'

import express from 'express'

const PORT = 3000

const secretKey = readFileSync('secret-key.txt', 'utf-8')

const app = express()

app.set('view engine', 'ejs')

app.use(express.urlencoded({ extended: true }))

app.get('/', (_req, res) => {
    res.render('index')
})

const safeCompare = (a, b) => {
    a = Buffer.from(a, 'utf-8')
    b = Buffer.from(b, 'utf-8')

    return a.length === b.length && timingSafeEqual(a, b)
}

app.post('/execute', (req, res) => {
    const { token, script } = req.body

    if (typeof token !== 'string' || typeof script !== 'string') {
        return res.render('execute', {
            error: 'Token and script must be provided and must be strings.'
        })
    }

    if (!script.trim().length) {
        return res.render('execute', {
            error: 'Please provide a script to execute.'
        })
    }

    const hash = createHash('sha256')
        .update(secretKey)
        .update(Buffer.from(script.replaceAll('\r\n', '\n'), 'binary'))

    if (!safeCompare(hash.digest('hex'), token)) {
        return res.render('execute', {
            error: 'Script token is invalid! ' +
                'Contact a Cinnamon Dynamics employee to get your script ' +
                'approved and receive a valid token for it.'
        })
    }

    const child = spawn('deno', ['run', '--allow-read=.', '-'], {
        cwd: join(process.cwd(), 'files'),
        env: { ...process.env, NO_COLOR: 1 }
    })

    let stdout = ''
    let stderr = ''

    child.stdout.on('data', data => stdout += data.toString('utf-8'))
    child.stderr.on('data', data => stderr += data.toString('utf-8'))

    child.stdin.write(req.body.script)
    child.stdin.end()

    let timedOut = false

    child.on('exit', exitCode => {
        res.render('execute', {
            error: timedOut ? 'Process timed out.' : null,
            stdout: stdout.trim(),
            stderr: stderr.trim(),
            exitCode
        })
    })

    setTimeout(() => {
        if (!child.killed) {
            timedOut = true
            child.kill('SIGKILL')
        }
    }, 1_000)
})

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`))

```

Basically, the server takes the script, prepends a secret of unknown length to the script, and hashes it. If the hash doesn't match the user-inputted token, it doesn't execute the script.  

If you navigate to the site, the user is presented with 4 different scripts and corresponding tokens to execute. Most notably, there is one titled "Unfinished Script":  

```
const file = await Deno.readTextFile('sales.txt')

const sales = file.split('\n')

console.log('Number of sales:', sales.length)

// TODO: finish this script
```

Notably, there is a comment at the end of this script, which would allow any bytes we put there to be ignored when the script is executed.  

This, in fact, is an instance of a well-known attack -- a hash length extension attack. A hash length extension attack works on various hashes, including the SHA family, and essentially allows you to "extend" a given plaintext by a user-chosen string and calculate the corresponding hash if the provided hash is equal to `hash(secret + plaintext)`.  

I won't explain it, but there are a lot of good resources online explaining how it works. [This](https://github.com/stephenbradshaw/hlextend) is what I used to solve it though.  

Also note that we have to brute-force the length of the hash, which is what I do in the solve script. Also also I spent an hour trying to figure out how to send the payload properly until I realized the answer was just to do `.decode('latin')`.  

```py
from hashlib import sha256
import string
from tqdm import trange
import hlextend
from requests import post

f = open('unfinished-script.txt', 'rb').read().replace(b'\r\n', b'\n')
ct = 'd649728e5f43a2cf8c6ec863bb48328a060c2f1ddb91976d6d138eac8ab91684' # unfinished script token

# NOTE: figure out secret length
# for slen in range(1, 257):
#     sha = hlextend.new('sha256')
#     res = sha.extend(b'idk', f, slen, ct)
#     res = res.decode('latin')
#     print(res)
#     print(sha.hexdigest())
#     response = post('http://challs.bcactf.com:31077/execute', {'token':sha.hexdigest(), 'script': res})
#     if "invalid" not in response.text:
#         print(slen)
#         break

slen = 31
payload = b"""
const a = await Deno.readTextFile('flag.txt')
console.log(a)
"""
sha = hlextend.new('sha256')
res = sha.extend(payload, f, slen, ct).decode('latin')
response = post('http://challs.bcactf.com:31077/execute', {'token':sha.hexdigest(), 'script': res})
print(response.text)
```

    bcactf{Th1S_I5_JuST_4_l1TtLe_t0o_1N5ECur3_95af828f32}