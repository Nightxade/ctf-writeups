---
layout: writeup
category: ping-CTF-2023
chall_description: N/A
points: 50
solves: 170
tags: web robots.txt path
date: 2023-12-11
comments: false
---

Can you pass the path traversal exam? 👀 There might be some requirements tho for your *specie*...  

[https://path-traversal-101.knping.pl](https://path-traversal-101.knping.pl)  

[ec96a2a4ee45dd97dfa37319f21468a3.zip](https://github.com/Nightxade/ctf-writeups/assets/CTFs/ping-CTF-2023/ec96a2a4ee45dd97dfa37319f21468a3.zip)  

---

We're given a zip file containing the source files for the website. Let's take a look.  

Firstly, `robot.js`:  

```js
export default (req, res, next) => {
    const userAgent = req.get("User-Agent");
    if (userAgent == "robot") {
        next();
    } else {
        res.render("robot", { error: "🤖🤖🤖🤖🤖" });
    }
};
```

Seems like we need to change our User-Agent to `robot`. This can easily be done with the Google Chrome extensions [Requestly](https://chromewebstore.google.com/detail/requestly-open-source-htt/mdnleldcmiljblolnjhpnblkcekpdkpa?pli=1) or with BurpSuite. I chose to do it with Requestly.  

To do it with Requestly, create a new rule to modify HTTP Request Headers, and modify User-Agent to `robot`. Reloading the page now gets us in!  

Now take a look at `index.js`:  

```js
import express from "express";
import { randomUUID } from "crypto";
import withCatch from "./withCatch.js";
import { task1, task2, task3, tasks } from "./tasks.js";
import cookieParser from "cookie-parser";

import rl from "./ratelimit.js";
import robot from "./robot.js";

const { FLAG } = process.env;

const app = express();
const port = 3000;

const sessions = [];

const createSession = () => {
    const id = randomUUID();
    return {
        id,
        task1: false,
        task2: false,
        task3: false,
    };
};

app.set("view engine", "ejs");
app.use(express.static("static"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
    res.render("robot", {
        error: "",
    });
});

app.get("/robots.txt", (req, res) => {
    res.type("text/plain");
    res.send("User-agent: *\nDisallow: /🤖");
});

app.get("/%F0%9F%A4%96", robot, (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        const session = createSession();
        sessions.push(session);
        res.cookie("token", session.id);
        res.render("exam", {
            task: tasks[0],
        });
    } else {
        const session = sessions.find((session) => session.id === token);
        if (!session) {
            const session = createSession();
            sessions.push(session);
            res.cookie("token", session.id);
            res.render("exam", {
                task: tasks[0],
            });
        } else {
            if (!session.task1) {
                res.render("exam", {
                    task: tasks[0],
                });
            } else if (!session.task2) {
                res.render("exam", {
                    task: tasks[1],
                });
            } else if (!session.task3) {
                res.render("exam", {
                    task: tasks[2],
                });
            } else {
                res.render("exam", {
                    task: FLAG,
                });
            }
        }
    }
});

app.get("/*", (req, res) => {
    res.render("robot", {
        error: "",
    });
});

app.post(
    "/%F0%9F%A4%96",
    rl,
    robot,
    withCatch(async (req, res) => {
        const token = req.cookies.token;
        if (!token) {
            throw new Error("Unauthorized");
        }
        const session = sessions.find((session) => session.id === token);
        if (!session) {
            throw new Error("Unauthorized");
        }
        const { solution } = req.body;
        if (!session.task1) {
            const result = task1(solution);
            if (result) {
                session.task1 = true;
                res.render("exam", {
                    task: tasks[1],
                });
            } else {
                res.render("exam", {
                    task: tasks[0],
                    error: "Try again!",
                });
            }
        } else if (!session.task2) {
            const result = task2(solution);
            if (result) {
                session.task2 = true;
                res.render("exam", {
                    task: tasks[2],
                });
            } else {
                res.render("exam", {
                    task: tasks[1],
                    error: "Try again!",
                });
            }
        } else if (!session.task3) {
            const result = task3(solution);
            if (result) {
                session.task3 = true;
                res.render("exam", {
                    task: FLAG,
                });
            } else {
                res.render("exam", {
                    task: tasks[2],
                    error: "Try again!",
                });
            }
        }
    })
);

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
```

Immediately, we can notice that at `/robots.txt`, `/🤖` is disallowed from web crawling. Visiting that site presents us with our first task of `tasks.js`. Here's `tasks.js` for reference:  

```js
import path from "path";

const preTask = (solution) => {
    if (typeof solution !== "string") {
        throw new Error("Solution must be a string");
    }
    if (solution.length > 512) {
        throw new Error("Solution must be less than 512 characters");
    }
    if (solution === "flag") {
        throw new Error("Your solution can't be 'flag'");
    }
    if (solution === "./flag") {
        throw new Error("Your solution can't be './flag'");
    }
};

export const task1 = (solution) => {
    preTask(solution);
    if (!solution.startsWith("/robot") || solution.endsWith("/flag")) {
        throw new Error(
            "You cannot access the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
        );
    }

    const solutionPath = path.join("/", solution);
    return solutionPath === "/flag";
};

export const task2 = (solution) => {
    preTask(solution);
    solution = solution.replaceAll("../", "");
    if (solution === "/flag") {
        throw new Error(
            "You cannot ACCESS the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
        );
    }

    const solutionPath = path.join("/", solution);
    return solutionPath === "/flag";
};

export const task3 = (solution) => {
    preTask(solution);
    if (solution.includes("../") || solution === "/flag") {
        throw new Error(
            "You CANNOT ACCESS the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
        );
    }

    const solutionPath = path.join("/", solution);
    return solutionPath === "/flag";
};

export const tasks = [
    `if (!solution.startsWith("/robot") || solution.endsWith("/flag")) {
    throw new Error(
        "You cannot access the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
    );
}

const solutionPath = path.join("/", solution);
return solutionPath === "/flag";`,
    `solution = solution.replaceAll("../", "");
    if (solution === "/flag") {
        throw new Error(
            "You cannot ACCESS the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
        );
    }

    const solutionPath = path.join("/", solution);
    return solutionPath === "/flag";`,
    `if (solution.includes("../") || solution === "/flag") {
    throw new Error(
        "You CANNOT ACCESS the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
    );
}

const solutionPath = path.join("/", solution);
return solutionPath === "/flag";`,
];
```

Let's take a look at task 1:  

```js
export const task1 = (solution) => {
    preTask(solution);
    if (!solution.startsWith("/robot") || solution.endsWith("/flag")) {
        throw new Error(
            "You cannot access the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
        );
    }

    const solutionPath = path.join("/", solution);
    return solutionPath === "/flag";
};
```

Firstly, to locally test our solution, it's easy to use a Node.js compiler like [this](https://www.tutorialspoint.com/execute_nodejs_online.php) and run each task there. Just note that importing the `path` module requires the use of this statement: `var path = require('path');`, not the one they provide in `tasks.js`.  

Now let's develop our solution. The first one requires that our path start with `/robot` and *not* end with `/flag`. This can be pretty easily done with `..`, which allows us to traverse backwards. Thus, we can construct the following string:  

`/robot/../flag/a/..`

The idea here is that `/robot/..` travels into and then out of the `robot` directory, while `/a/..` travels into and then out of the `a` directory, leaving us with just `/flag`, our desired outcome!  

Here's task 2:  

```js
export const task2 = (solution) => {
    preTask(solution);
    solution = solution.replaceAll("../", "");
    if (solution === "/flag") {
        throw new Error(
            "You cannot ACCESS the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
        );
    }

    const solutionPath = path.join("/", solution);
    return solutionPath === "/flag";
};
```

Task two seems to just be removing all `../` and replacing them with black spaces. Once the removal is done it simply checks if the result of the replacement is `/flag`. After solving this and moving onto task 3, I realized that the intended solution was probably the following payload:  

`/flag/a/....//`

The reason this would work is because the replace operation would actually result in the following:  

`/flag/a/../`

Which would evaluate as a path to the flag. However, I actually found a different solution:  

`//flag`

The first forward slash doesn't actually do anything to change the path, so this works just fine to pass task 2!  

Here's task 3:  

```js
export const task3 = (solution) => {
    preTask(solution);
    if (solution.includes("../") || solution === "/flag") {
        throw new Error(
            "You CANNOT ACCESS the flag!!! You are UNAUTHORIZED!!! 🤖🤖🤖🤖🤖"
        );
    }

    const solutionPath = path.join("/", solution);
    return solutionPath === "/flag";
};
```

Conveniently, because I found the unintended solution to task 2, my solution there worked completely fine here as well.  

`//flag`

Once I completed the final task, the website presented me with the flag!  

    ping{p4th_tr4V3Rs4L_06c22f693acd46015891c98cb72f45e3}