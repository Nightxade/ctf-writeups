---
layout: writeup
category: Dice-CTF-Quals-2024
chall_description: 
points: 105
solves: 445
tags: web inspect
date: 2024-2-4
comments: false
---

Follow the leader.  

[ddg.mc.ax](https://ddg.mc.ax/)  

---

Visit the site. Seems like some sort of game. Heading to Chrome Dev Tools with Inspect, there is a source file for (index):  

```html
<script src="/mojojs/mojo_bindings.js"></script>
<script src="/mojojs/gen/third_party/blink/public/mojom/otter/otter_vm.mojom.js"></script>

<script src="/prog.js"></script>

<style>
  #game {
    padding-top: 50px;
  }

  .row {
    display: flex;
    justify-content: center;
  }

  .grid {
    width: 30px;
    height: 30px;
    border: 1px solid rgba(0, 0, 0, 0.1);
  }

  .goose {
    background-color: black;
  }
  .wall {
    background-color: green;
  }

  .dice {
  }

  #displaywrapper {
    width: 100%;
    top: 50px;
    position: absolute;
  }
  #display {
    width: 500px;
    height: 300px;
    margin: 0 auto;
    background-color: rgba(255, 255, 255, 0.7);
    text-align: center;
  }
  #display h1 {
  }
  .hidden {
    display: none;
  }

  #scoreboard {
    text-align: center;
    margin-top: 50px;
  }

  #title {
    text-align: center;
  }
</style>

<h1 id="title">DDG: The Game</h1>
<div id="game"></div>
<div id="displaywrapper" class="hidden">
  <div id="display">
    <h1>You Won!</h1>
    <p></p>
    <a href="">Brag on Twitter</a>
  </div>
</div>
<div id="scoreboard"></div>

<script>
  var icons = [
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgBAMAAACBVGfHAAAAD1BMVEUAAADDGBgwMDD%2F%2F%2F%2FNMzNpjlSGAAAAAXRSTlMAQObYZgAAAJJJREFUKM%2Bd0dEJgyEQA2DpBncuoKELyI3Q%2FXdqzO%2FVVv6nBgTzEXyx%2FBsw7as%2FYD5t924M8QPqMWzJHNSwMGANXmzBDVyAJ2EG3Zsg3%2BxG0JOQwRbMO6NdAuOwA3odB8Qd4IIaBPkBdcMQRIIlDIG2ZhyOXCjg8XIADvB2AC5AX6CBBAIHIYUrAL8%2Fl32PWrnNGwkeH2HFm0NCAAAAAElFTkSuQmCC",
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgAgMAAAAOFJJnAAAADFBMVEUAAADDGBgwMDD%2F%2F%2F8aApG0AAAAAXRSTlMAQObYZgAAAJZJREFUGNNtzzEOgzAMBdAoI0fpfX6QvLAW9o4ILkFnllTk3yfqSdq1tZMipAovfrIs2d%2BdFtfaG3IruCCUmY8AOCuANhsadM%2F3Y9WVT5flruAICFbnmYDeAC6IuOquMCwFGIgKpPaHftox7rgVTBCMBfkfneJlsJt6q4mGMDufDKIf0jBYmqjYahwJs8FTxNWE5BH%2BqC8RZ01veWxOMgAAAABJRU5ErkJggg%3D%3D",
  ];
  var imageIdx = 0;
  function run() {
    for (let item of document.getElementsByClassName("dice")) {
      item.style.backgroundImage = "url('" + icons[imageIdx++ % 2] + "')";
    }
  }

  setInterval(run, 200);

  let X = 11;
  let Y = 20;

  let player = [0, 1];
  let goose = [9, 9];

  let walls = [];
  for (let i = 0; i < 9; i++) {
    walls.push([i, 2]);
  }

  let history = [];
  history.push([player, goose]);

  const log = (msg) => {
    console.log(msg);
    fetch("/log?log=" + encodeURIComponent(msg));
  };

  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  window.onerror = (e) => log(e);

  for (let i = 0; i < X; i++) {
    var row = document.createElement("div");
    row.className = "row";
    for (let i = 0; i < Y; i++) {
      var elem = document.createElement("div");
      elem.className = "grid";

      row.appendChild(elem);
    }
    game.appendChild(row);
  }

  function redraw() {
    for (let item of document.getElementsByClassName("grid")) {
      item.className = "grid";
      item.style.backgroundImage = "";
    }

    game.children[player[0]].children[player[1]].className = "grid dice";
    game.children[goose[0]].children[goose[1]].className = "grid goose";

    for (let item of document.getElementsByClassName("dice")) {
      item.style.backgroundImage = "url('" + icons[imageIdx++ % 2] + "')";
    }

    for (const wall of walls) {
      game.children[wall[0]].children[wall[1]].className = "grid wall";
    }
  }

  function isValid(pos) {
    if (pos[0] < 0 || pos[0] >= X) return false;
    if (pos[1] < 0 || pos[1] >= Y) return false;

    for (const wall of walls) {
      if (pos[0] === wall[0] && pos[1] === wall[1]) return false;
    }

    return true;
  }

  redraw();

  let won = false;
  document.onkeypress = (e) => {
    if (won) return;

    let nxt = [player[0], player[1]];

    switch (e.key) {
      case "w":
        nxt[0]--;
        break;
      case "a":
        nxt[1]--;
        break;
      case "s":
        nxt[0]++;
        break;
      case "d":
        nxt[1]++;
        break;
    }

    if (!isValid(nxt)) return;

    player = nxt;

    if (player[0] === goose[0] && player[1] === goose[1]) {
      win(history);
      won = true;
      return;
    }

    do {
      nxt = [goose[0], goose[1]];
      switch (Math.floor(4 * Math.random())) {
        case 0:
          nxt[0]--;
          break;
        case 1:
          nxt[1]--;
          break;
        case 2:
          nxt[0]++;
          break;
        case 3:
          nxt[1]++;
          break;
      }
    } while (!isValid(nxt));

    goose = nxt;

    history.push([player, goose]);

    redraw();
  };

  function encode(history) {
    const data = new Uint8Array(history.length * 4);

    let idx = 0;
    for (const part of history) {
      data[idx++] = part[0][0];
      data[idx++] = part[0][1];
      data[idx++] = part[1][0];
      data[idx++] = part[1][1];
    }

    let prev = String.fromCharCode.apply(null, data);
    let ret = btoa(prev);
    return ret;
  }

  function win(history) {
    const code = encode(history) + ";" + prompt("Name?");

    const saveURL = location.origin + "?code=" + code;
    displaywrapper.classList.remove("hidden");

    const score = history.length;

    display.children[1].innerHTML = "Your score was: <b>" + score + "</b>";
    display.children[2].href =
      "https://twitter.com/intent/tweet?text=" +
      encodeURIComponent(
        "Can you beat my score of " + score + " in Dice Dice Goose?",
      ) +
      "&url=" +
      encodeURIComponent(saveURL);

    if (score === 9) log("flag: dice{pr0_duck_gam3r_" + encode(history) + "}");
  }

  const replayCode = new URL(location.href).searchParams.get("code");

  if (replayCode !== null) replay();

  let validated = false;
  async function replay() {
    if (!(await validate())) {
      log("Failed to validate");
      return;
    }


    won = true;

    const replay = atob(replayCode.split(";")[0]);
    const name = replayCode.split(";")[1];

    title.innerText =
      "DDG: The Replay (" + name + ") " + (validated ? "" : "[unvalidated]");

    let idx = 0;

    setInterval(() => {
      player = [replay.charCodeAt(idx), replay.charCodeAt(idx + 1)];
      goose = [replay.charCodeAt(idx + 2), replay.charCodeAt(idx + 3)];

      redraw();

      idx += 4;
      if (idx >= replay.length) idx = 0;
    }, 500);

    scoreboard.innerHTML = "<b>" + winner.name + "</b>: " + winner.score;
  }

  let winner = {
    score: 4,
    name: "warley the winner winner chicken dinner",
  };

  async function validate() {
    if (typeof Mojo === "undefined") {
      return true;
    }
    try {
      log("starting " + Math.random());

      const ptr = new blink.mojom.OtterVMPtr();
      Mojo.bindInterface(
        blink.mojom.OtterVM.name,
        mojo.makeRequest(ptr).handle,
      );

      await sleep(100);

      const replay = atob(replayCode.split(";")[0]);
      const name = replayCode.split(";")[1];

      let data = new Uint8Array(code.length);
      for (let i = 0; i < code.length; i++) data[i] = code.charCodeAt(i);

      await ptr.init(data, entrypoint);
      data = new Uint8Array(1_024 * 11);
      data[0] = 1;

      idx = 8;
      data[idx++] = 0xff;
      data[idx++] = 0;
      data[idx++] = 0;
      data[idx++] = 0;
      idx += 4;
      idx += 32;
      idx += 32;
      idx += 8;

      data_idx = idx;

      LEN = 8 + 4 + winner.name.length;
      data[idx++] = LEN;
      idx += 7;

      data[idx] = winner.score;
      idx += 8;
      data[idx] = winner.name.length;
      idx += 4;

      for (let i = 0; i < winner.name.length; i++) {
        data[idx + i] = winner.name.charCodeAt(i);
      }
      idx += winner.name.length;

      idx += 1024 * 10;

      idx += (8 - (idx % 8)) % 8;

      idx += 8;

      LEN = 4 + name.length + 4 + replay.length;
      data[idx++] = LEN;
      idx += 7;

      data[idx++] = name.length;
      idx += 3;
      for (let i = 0; i < name.length; i++) {
        data[idx + i] = name.charCodeAt(i);
      }
      idx += name.length;

      data[idx++] = replay.length;
      idx += 3;
      for (let i = 0; i < replay.length; i++) {
        data[idx + i] = replay.charCodeAt(i);
      }
      idx += replay.length;

      idx += 32; // pubkey

      data[idx] = 0;

      var resp = (await ptr.run(data)).resp;

      if (resp.length === 0) {
        return false;
      }

      data_idx += 8;

      let num = 0;
      let cnter = 1;
      for (let i = data_idx; i < data_idx + 8; i++) {
        num += cnter * resp[i];
        cnter *= 0x100;
      }
      data_idx += 8;

      winner.score = num;

      num = 0;
      cnter = 1;
      for (let i = data_idx; i < data_idx + 4; i++) {
        num += cnter * resp[i];
        cnter *= 0x100;
      }

      data_idx += 4;

      len = num;
      let winnerName = "";
      for (let i = data_idx; i < data_idx + len; i++) {
        winnerName += String.fromCharCode(resp[i]);
      }

      winner.name = winnerName;

      return true;
    } catch (e) {
      log("error");
      log(": " + e.stack);
    }
  }
</script>

```

Immediately, we can see that the main logic of the program is contained within the `<script>` tags. Notably, we see how to win here:  

```js
if (score === 9) log("flag: dice{pr0_duck_gam3r_" + encode(history) + "}");
```

However, if you played the game, you would know that the score variable refers to the number of moves the player made to catch the "goose". Unfortunately, it's clear that 9 moves is near impossible, as it would require the goose to move left 8 times in a row, i.e. a 1/4**8 = 1/65536 chance. So how can we get to 9 moves?  

We could calculate the resultant array for `history` and put it in to the encode function to get our answer, but we can do something even nicer! On Chrome, by right-clicking on the source file and hitting "Override content", we can change the source code of the site and run it in our browser!  

This allows us to modify the code that controls the goose's movement to this:  

```js
do {
    nxt = [goose[0], goose[1]];
    nxt[1]--;
} while (!isValid(nxt));
```

This ensures that the goose only moves right. Save the file, reload the page, and move down 9 times. Check the console and get the flag!  

    dice{pr0_duck_gam3r_AAEJCQEBCQgCAQkHAwEJBgQBCQUFAQkEBgEJAwcBCQIIAQkB}