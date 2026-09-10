/* Vault Defense — ClaudePass landing-page hero game.
 * Vanilla JS, single <canvas>, zero dependencies, procedural pixel art.
 * Fixed 240x256 internal resolution (15x15 tile playfield + 16px HUD strip).
 * See site/index.html for markup this script attaches to.
 */
(function () {
  "use strict";

  var TILE = 16, COLS = 15, ROWS = 15, FIELD_W = COLS * TILE, FIELD_H = ROWS * TILE;
  var CANVAS_W = FIELD_W, CANVAS_H = FIELD_H + 16; // +16 HUD strip
  var STEP_MS = 1000 / 60;
  var MAX_CATCHUP = 5;

  var canvas = document.getElementById("vault-defense");
  if (!canvas) return;
  var ctx = canvas.getContext("2d", { alpha: false });
  ctx.imageSmoothingEnabled = false;

  var overlayPrompt = document.getElementById("play-overlay");
  var muteBtn = document.getElementById("mute-toggle");
  // CRT overlay + its two toggle controls are owned by site.js (shared
  // across every page); game.js only owns audio, which needs the real
  // AudioContext this closure holds.

  var hudScore = document.getElementById("hud-score");
  var hudHi = document.getElementById("hud-hiscore");
  var hudWave = document.getElementById("hud-wave");
  var hudLives = document.getElementById("hud-lives");
  var tickerLine = document.getElementById("hiscore-ticker-line");
  // The mobile install bar itself is owned by site.js (shared across
  // pages); we just broadcast score changes for it to pick up.

  var dpad = document.querySelector(".dpad");
  var fireBtn = document.querySelector(".fire-btn");
  var gameOverCta = document.getElementById("game-over-cta");

  // ---------------------------------------------------------------
  // Storage (guarded — localStorage can throw in private/blocked contexts)
  // ---------------------------------------------------------------
  var LS_MUTED = "vaultdefense.muted";
  var LS_SCORES = "vaultdefense.hiscores.v1";

  function lsGet(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function lsSet(key, val) {
    try { window.localStorage.setItem(key, val); } catch (e) { /* ignore */ }
  }
  function loadScores() {
    try {
      var raw = window.localStorage.getItem(LS_SCORES);
      var arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr : [];
    } catch (e) { return []; }
  }
  function saveScores(arr) {
    try { window.localStorage.setItem(LS_SCORES, JSON.stringify(arr)); } catch (e) { /* ignore */ }
  }
  function topScore() {
    var s = loadScores();
    return s.length ? s[0].score : 0;
  }

  // ---------------------------------------------------------------
  // Reduced motion
  // ---------------------------------------------------------------
  var motionOK = true;
  var mq = null;
  try {
    mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    motionOK = !mq.matches;
    var mqHandler = function () { motionOK = !mq.matches; };
    if (mq.addEventListener) mq.addEventListener("change", mqHandler);
    else if (mq.addListener) mq.addListener(mqHandler);
  } catch (e) { motionOK = true; }

  // ---------------------------------------------------------------
  // Audio — WebAudio square waves only, muted by default.
  // ---------------------------------------------------------------
  var muted = lsGet(LS_MUTED) !== "0"; // default true unless explicitly unmuted before
  var audioCtx = null, masterGain = null;
  function ensureAudio() {
    if (audioCtx) return;
    try {
      var AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return;
      audioCtx = new AC();
      masterGain = audioCtx.createGain();
      masterGain.gain.value = muted ? 0 : 0.18;
      masterGain.connect(audioCtx.destination);
    } catch (e) { audioCtx = null; }
  }
  function setMuted(v) {
    muted = v;
    lsSet(LS_MUTED, v ? "1" : "0");
    if (masterGain) masterGain.gain.value = v ? 0 : 0.18;
    if (muteBtn) {
      muteBtn.setAttribute("aria-pressed", v ? "false" : "true");
      muteBtn.textContent = v ? "🔇" : "🔊";
      muteBtn.setAttribute("aria-label", v ? "Unmute sound" : "Mute sound");
    }
  }
  function beep(freq, dur, type, delay, gainMul) {
    if (muted || !audioCtx) return;
    var t0 = audioCtx.currentTime + (delay || 0);
    var osc = audioCtx.createOscillator();
    var g = audioCtx.createGain();
    osc.type = type || "square";
    osc.frequency.setValueAtTime(freq, t0);
    g.gain.setValueAtTime((gainMul || 1) * 0.5, t0);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    osc.connect(g);
    g.connect(masterGain);
    osc.start(t0);
    osc.stop(t0 + dur + 0.02);
  }
  function sweep(f0, f1, dur) {
    if (muted || !audioCtx) return;
    var t0 = audioCtx.currentTime;
    var osc = audioCtx.createOscillator();
    var g = audioCtx.createGain();
    osc.type = "square";
    osc.frequency.setValueAtTime(f0, t0);
    osc.frequency.exponentialRampToValueAtTime(f1, t0 + dur);
    g.gain.setValueAtTime(0.4, t0);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    osc.connect(g); g.connect(masterGain);
    osc.start(t0); osc.stop(t0 + dur + 0.02);
  }
  function sfxKill() { sweep(400, 100, 0.14); }
  function sfxShot() { beep(880, 0.06, "square"); }
  function sfxHit() { beep(140, 0.08, "square"); }
  function sfxPowerup() {
    beep(440, 0.06, "square", 0); beep(554, 0.06, "square", 0.06);
    beep(659, 0.06, "square", 0.12); beep(880, 0.08, "square", 0.18);
  }
  function sfxWaveClear() {
    beep(523, 0.09, "square", 0); beep(659, 0.09, "square", 0.09); beep(784, 0.14, "square", 0.18);
  }
  function sfxBreach() {
    beep(220, 0.14, "square", 0); beep(180, 0.14, "square", 0.16);
  }
  function sfxGameOver() {
    beep(392, 0.16, "square", 0); beep(349, 0.16, "square", 0.16);
    beep(294, 0.16, "square", 0.32); beep(220, 0.24, "square", 0.48);
  }

  // ---------------------------------------------------------------
  // Palette
  // ---------------------------------------------------------------
  var PAL = {
    phosphor: "#33ff66", phosphorDim: "#1f9e44", cyan: "#4de8ff",
    red: "#ff4d4d", redDim: "#b32424", yellow: "#ffe94d",
    steel: "#6b7280", void_: "#0a0e0a", panel: "#10160f",
    trackDark: "#0e4d1f", trackDarkRed: "#5c1a1a", white: "#e8f3ea"
  };

  // ---------------------------------------------------------------
  // Procedural sprites — string-array bitmaps, one facing ("up") per
  // type; other facings are produced with ctx.rotate at draw time.
  // Rasterized once onto offscreen canvases at boot (sprite cache).
  // ---------------------------------------------------------------
  function tankRows(w, trackW) {
    // Generic top-down tank silhouette, symmetric, parameterized by width.
    var rows = [];
    var half = w / 2;
    function row(str) { rows.push(str); }
    var pad1 = Math.floor(half - 1);
    row(rep(".", pad1) + "HH" + rep(".", w - pad1 - 2));
    row(rep(".", pad1) + "HH" + rep(".", w - pad1 - 2));
    var pad2 = Math.floor(half - 2);
    row(rep(".", pad2) + "HHHH" + rep(".", w - pad2 - 4));
    var hullW = w - trackW * 2;
    row(rep(".", trackW) + rep("H", hullW) + rep(".", trackW));
    var bodyRows = w === 14 ? 7 : w === 15 ? 8 : 10;
    for (var i = 0; i < bodyRows; i++) {
      row(rep("C", trackW) + rep("H", hullW) + rep("C", trackW));
    }
    row(rep(".", trackW) + rep("H", hullW) + rep(".", trackW));
    row(rep(".", w));
    while (rows.length < w) row(rep(".", w));
    return rows;
  }
  function rep(ch, n) { return n > 0 ? new Array(n + 1).join(ch) : ""; }

  var SPR = {
    playerA: { rows: tankRows(16, 3), map: { H: PAL.phosphor, C: PAL.trackDark } },
    playerB: null, // built below with tread offset
    scout: { rows: tankRows(14, 2), map: { H: PAL.red, C: PAL.trackDarkRed } },
    reader: { rows: tankRows(15, 2), map: { H: PAL.redDim, C: PAL.trackDarkRed } },
    shouter: { rows: tankRows(16, 3), map: { H: PAL.red, C: PAL.trackDarkRed } },
    saboteur: { rows: tankRows(16, 3), map: { H: PAL.red, C: PAL.trackDarkRed } },
    readerHard: { rows: tankRows(15, 2), map: { H: PAL.redDim, C: PAL.steel } },
    shouterHard: { rows: tankRows(16, 3), map: { H: PAL.red, C: PAL.steel } },
    brick1: { rows: brickRows(false), map: { B: PAL.steel, D: PAL.trackDark } },
    brick2: { rows: brickRows(true), map: { B: PAL.steel, D: PAL.trackDark } },
    steelWall: { rows: steelRows(), map: { S: PAL.steel, L: "#9aa1a8" } },
    shieldIcon: { rows: hexRows(), map: { X: PAL.cyan } },
    barricadeIcon: { rows: shieldRows(), map: { X: PAL.cyan, Y: PAL.yellow } },
    manifestIcon: { rows: scrollRows(), map: { X: PAL.yellow } }
  };
  // Frame B: shift two tread pixels to fake track movement.
  (function () {
    var rows = SPR.playerA.rows.slice();
    function toggle(idx) {
      var r = rows[idx];
      rows[idx] = r.substr(0, 1) + "." + r.substr(2, r.length - 4) + "." + r.substr(r.length - 1);
    }
    toggle(7); toggle(10);
    SPR.playerB = { rows: rows, map: SPR.playerA.map };
  })();

  function brickRows(damaged) {
    if (!damaged) return ["BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD", "BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD",
      "BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD", "BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD",
      "BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD", "BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD",
      "BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD", "BBBBBBBBBBBBBBBB", "BDBDBDBDBDBDBDBD"];
    return ["D...D...D...D...".split("").slice(0, 16).join(""), "................",
      "..D...D...D...D.", "................", "D...D...D...D...", "................",
      "..D...D...D...D.", "................", "D...D...D...D...", "................",
      "..D...D...D...D.", "................", "D...D...D...D...", "................",
      "................", "................"];
  }
  function steelRows() {
    var r = [];
    for (var i = 0; i < 16; i++) r.push(i % 4 === 0 ? "LSSSLSSSLSSSLSSS" : "SSSSSSSSSSSSSSSS");
    return r;
  }
  function hexRows() {
    return [".....XXXX.......", "...XXXXXXXX.....", "..XXXXXXXXXX....",
      "..XX......XX....", "..XX......XX....", "..XXXXXXXXXX....",
      "...XXXXXXXX.....", ".....XXXX......."].map(function (r) { return (r + "........").slice(0, 8); });
  }
  function shieldRows() {
    return ["..XXXXXX", ".XYYYYXX", "XYXXXXXY", "XYXYYXXY", "XYXYYXXY", "XYXXXXXY", ".XYYYYX.", "..XXXX.."];
  }
  function scrollRows() {
    return ["XXXXXXXX", "X......X", "X.XXXX.X", "X.X..X.X", "X.XXXX.X", "X......X", "X......X", "XXXXXXXX"];
  }

  var cache = {};
  function rasterize(spr) {
    var rows = spr.rows, h = rows.length, w = rows[0].length;
    var off = document.createElement("canvas");
    off.width = w; off.height = h;
    var octx = off.getContext("2d");
    var img = octx.createImageData(w, h);
    for (var y = 0; y < h; y++) {
      var row = rows[y];
      for (var x = 0; x < w; x++) {
        var ch = row[x];
        if (ch === "." || ch === undefined) continue;
        var color = spr.map[ch];
        if (!color) continue;
        var rgb = hexToRgb(color);
        var i = (y * w + x) * 4;
        img.data[i] = rgb[0]; img.data[i + 1] = rgb[1]; img.data[i + 2] = rgb[2]; img.data[i + 3] = 255;
      }
    }
    octx.putImageData(img, 0, 0);
    return off;
  }
  function hexToRgb(hex) {
    var v = parseInt(hex.replace("#", ""), 16);
    return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
  }
  Object.keys(SPR).forEach(function (k) { cache[k] = rasterize(SPR[k]); });

  function drawSpriteRotated(name, cx, cy, angleDeg, invert) {
    var img = cache[name];
    if (!img) return;
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate((angleDeg * Math.PI) / 180);
    if (invert) ctx.filter = "invert(1)";
    ctx.drawImage(img, -img.width / 2, -img.height / 2);
    ctx.restore();
  }
  var DIR_ANGLE = { up: 0, right: 90, down: 180, left: 270 };

  // ---------------------------------------------------------------
  // Entities
  // ---------------------------------------------------------------
  var TYPES = {
    scout: { hp: 1, speed: 48, score: 100, w: 14, h: 14, sprite: "scout" },
    reader: { hp: 2, speed: 40, score: 150, w: 15, h: 15, sprite: "reader" },
    shouter: { hp: 2, speed: 32, score: 250, w: 16, h: 16, sprite: "shouter", fires: true },
    saboteur: { hp: 3, speed: 56, score: 500, w: 16, h: 16, sprite: "saboteur", erratic: true }
  };

  var VAULT = { x: FIELD_W / 2 - 16, y: FIELD_H - 32 - 4, w: 32, h: 32 };
  var HANDLES = ["stripe/live", "github/token", "aws/access-key"];
  var vaultLabelIdx = 0, vaultLabelT = 0, vaultBreachT = 0, vaultBreachHandle = "";

  var player, bullets, intruders, particles, redPops, powerups, walls, popups;
  var state, stateT, wave, score, hi, lives, combo, comboT, spawnQueue, spawnTimer, waveSpeedMul;
  var perfectWave, hitstop, shake, dropGiven, idleT;
  var input = { up: false, down: false, left: false, right: false, fire: false };
  var keysDown = {};
  var touchDirs = { up: false, down: false, left: false, right: false };
  var lastPressedDir = null;

  // ---------------------------------------------------------------
  // Debug instrumentation — read-only, zero effect on gameplay. Only
  // active when the page URL has ?debug=1, in which case it exposes
  // window.__vaultDefenseDebug() returning a live snapshot (state
  // machine, score, wave, lives, input/focus flags, live bullet and
  // intruder counts + types/hp, remaining spawn-queue length) plus the
  // last 20 collision-ish events (bullet_hit, kill, player_hit,
  // vault_breach, wave_start, wave_clear) with timestamps. Used by the
  // play-test harness to read ground truth instead of screen-scraping
  // the canvas. debugEvent() is a no-op unless DEBUG is true, and
  // nothing here ever mutates game state — safe to leave shipped.
  // ---------------------------------------------------------------
  var DEBUG = false;
  try { DEBUG = /(?:^|[?&])debug=1(?:&|$)/.test(window.location.search); } catch (e) { DEBUG = false; }
  var debugLog = [];
  function debugEvent(type, detail) {
    if (!DEBUG) return;
    debugLog.push({ t: Math.round(performance.now()), type: type, detail: detail });
    if (debugLog.length > 20) debugLog.shift();
  }
  if (DEBUG) {
    window.__vaultDefenseDebug = function () {
      return {
        state: state, stateT: stateT, wave: wave, score: score, hi: hi, lives: lives,
        canvasFocused: canvasFocused, input: { up: input.up, down: input.down, left: input.left, right: input.right, fire: input.fire },
        player: player ? { x: Math.round(player.x), y: Math.round(player.y), dir: player.dir, cooldown: player.cooldown } : null,
        bulletCount: bullets.length,
        bullets: bullets.map(function (b) { return { x: Math.round(b.x), y: Math.round(b.y), isPlayer: b.isPlayer }; }),
        intruderCount: intruders.length,
        intruders: intruders.map(function (iv) { return { type: iv.type, x: Math.round(iv.x), y: Math.round(iv.y), hp: iv.hp }; }),
        spawnQueueRemaining: spawnQueue ? spawnQueue.length : 0,
        events: debugLog.slice()
      };
    };
  }

  function resetRun() {
    player = { x: FIELD_W / 2 - 8, y: FIELD_H - 24, w: 16, h: 16, dir: "up", cooldown: 0, queuedShot: false,
      invuln: 0, shieldT: 0, tread: 0, treadT: 0, alive: true };
    bullets = []; intruders = []; particles = []; redPops = []; powerups = []; popups = [];
    walls = [];
    wave = 0; score = 0; lives = 3; combo = 1; comboT = 0;
    perfectWave = true; hitstop = 0; shake = 0; dropGiven = {};
    vaultLabelIdx = 0; vaultLabelT = 0; vaultBreachT = 0;
  }
  resetRun();
  hi = topScore();

  // ---------------------------------------------------------------
  // Wave table
  // ---------------------------------------------------------------
  // Wave 1 must be unlosable-if-you-try: a player who does nothing but
  // hold the default "up" facing and tap fire every ~300ms has to clear
  // it without losing a life, so the [REDACTED] pop lands on the very
  // first real attempt. That requires three things together, not just
  // "make it slow" — steerToVault flies each intruder in a straight
  // line from its spawn point to a fixed point just above the vault, so
  // a corner spawn (old behavior, every wave) only crosses a stationary
  // player's firing column in the last instant before reaching the
  // vault, however slow it moves: there is no speed low enough to make
  // that hittable. `spawnXRange` spawns wave 1-2 intruders in a band
  // centered on the player's default column instead, so the whole
  // straight-line path stays near that column. `speed` (a multiplier on
  // each type's base TYPES[x].speed, itself now correctly normalized —
  // see steerToVault) and `interval` (seconds between spawns, the real
  // spawn gap since intruders spawn one at a time) then set how
  // forgiving the encounter is. Waves 2-8 widen the spawn band back out
  // and ramp speed/count/interval gently as the mix adds tougher types.
  var WAVES = [
    { total: 5, mix: { scout: 5 }, interval: 2.5, speed: 0.55, walls: 0, spawnXRange: [88, 152] },
    { total: 7, mix: { scout: 5, reader: 2 }, interval: 2.2, speed: 0.70, walls: 1, spawnXRange: [56, 184] },
    { total: 9, mix: { scout: 4, reader: 3, shouter: 2 }, interval: 2.0, speed: 0.80, walls: 1, steel: true },
    { total: 11, mix: { scout: 3, reader: 4, shouter: 3, saboteur: 1 }, interval: 1.8, speed: 0.90, walls: 1, steel: true },
    { total: 13, mix: { scout: 2, reader: 4, shouter: 4, saboteur: 3 }, interval: 1.6, speed: 1.00, walls: 1, steel: true },
    { total: 15, mix: { scout: 1, reader: 4, shouter: 5, saboteur: 5 }, interval: 1.4, speed: 1.10, walls: 1, steel: true },
    { total: 17, mix: { scout: 1, reader: 3, shouter: 6, saboteur: 7 }, interval: 1.25, speed: 1.20, walls: 1, steel: true },
    { total: 19, mix: { scout: 0, reader: 4, shouter: 6, saboteur: 9 }, interval: 1.15, speed: 1.30, walls: 1, steel: true }
  ];

  function buildQueue(waveIdx) {
    var list = [];
    if (waveIdx < WAVES.length) {
      var w = WAVES[waveIdx];
      Object.keys(w.mix).forEach(function (t) {
        for (var i = 0; i < w.mix[t]; i++) list.push(t);
      });
    } else {
      var n = Math.min(28, 16 + 2 * (waveIdx + 1 - 8));
      var weights = { scout: 1, reader: 2, shouter: 3, saboteur: 3 + Math.min(waveIdx - 8, 6) };
      var keys = Object.keys(weights), total = keys.reduce(function (a, k) { return a + weights[k]; }, 0);
      for (var i = 0; i < n; i++) {
        var r = Math.random() * total, acc = 0, pick = keys[0];
        for (var j = 0; j < keys.length; j++) { acc += weights[keys[j]]; if (r <= acc) { pick = keys[j]; break; } }
        list.push(pick);
      }
    }
    return shuffle(list);
  }
  function pickSpawnX(cfg) {
    if (cfg.spawnXRange) return cfg.spawnXRange[0] + Math.random() * (cfg.spawnXRange[1] - cfg.spawnXRange[0]);
    return Math.random() < 0.5 ? 8 : FIELD_W - 24;
  }
  function shuffle(arr) {
    for (var i = arr.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
    return arr;
  }
  function waveConfig(waveIdx) {
    if (waveIdx < WAVES.length) return WAVES[waveIdx];
    var speedMul = Math.min(1.8, 1 + 0.04 * (waveIdx + 1 - 8));
    return {
      total: Math.min(28, 16 + 2 * (waveIdx + 1 - 8)),
      interval: Math.max(0.6, 1.8 - (waveIdx + 1) * 0.05),
      speed: speedMul, walls: 1, steel: true, hardened: waveIdx >= 8
    };
  }

  function startWave(idx) {
    wave = idx;
    var cfg = waveConfig(idx);
    spawnQueue = buildQueue(idx);
    spawnTimer = 0;
    waveSpeedMul = cfg.speed;
    perfectWave = true;
    dropGiven[idx] = false;
    walls = [];
    if (cfg.walls) placeBrickRing();
    if (cfg.steel) placeSteelCorners();
    debugEvent("wave_start", { wave: idx });
    popups.push({ text: "WAVE " + (idx + 1) + " — INCOMING", t: 0, dur: 1.4, y: FIELD_H / 2 - 20, color: PAL.phosphor });
  }
  function placeBrickRing() {
    var cx = VAULT.x, cy = VAULT.y;
    var ringTiles = [
      { x: cx - 16, y: cy - 16 }, { x: cx, y: cy - 16 }, { x: cx + 16, y: cy - 16 }, { x: cx + 32, y: cy - 16 },
      { x: cx - 16, y: cy }, { x: cx + 48, y: cy },
      { x: cx - 16, y: cy + 16 }, { x: cx + 48, y: cy + 16 }
    ];
    ringTiles.forEach(function (t) {
      if (t.x < 0 || t.x > FIELD_W - 16) return;
      // A second Barricade pickup in the same wave re-runs this to
      // repair any tiles already destroyed — it must not stack a
      // duplicate, still-intact tile on top of one that's still there,
      // which would silently double that spot's effective HP.
      if (wallAt(t.x, t.y)) return;
      walls.push({ x: t.x, y: t.y, w: 16, h: 16, hp: 2, type: "brick" });
    });
  }
  function wallAt(x, y) {
    for (var i = 0; i < walls.length; i++) {
      if (walls[i].x === x && walls[i].y === y) return true;
    }
    return false;
  }
  function placeSteelCorners() {
    walls.push({ x: 16, y: 16, w: 16, h: 16, type: "steel" });
    walls.push({ x: FIELD_W - 32, y: 16, w: 16, h: 16, type: "steel" });
  }

  // ---------------------------------------------------------------
  // State machine
  // ---------------------------------------------------------------
  var STATE = { BOOT: "BOOT", ATTRACT: "ATTRACT", PLAYING: "PLAYING", PAUSED: "PAUSED",
    WAVE_CLEAR: "WAVE_CLEAR", GAME_OVER: "GAME_OVER", ENTER_INITIALS: "ENTER_INITIALS" };
  state = STATE.BOOT; stateT = 0; idleT = 0;

  var attractScript = null;
  function buildAttractScript() {
    // ~8s scripted demo: patrol, kill one (pop [REDACTED]), let one breach,
    // then blink PRESS START. Deterministic, no real collision logic.
    return {
      t: 0,
      total: 8,
      phase: 0,
      spawned2: false
    };
  }

  var pausedByVisibility = false;
  function enterAttract() {
    resetRun();
    state = STATE.ATTRACT; stateT = 0; idleT = 0;
    attractScript = buildAttractScript();
    player.x = 40; player.y = FIELD_H - 60;
    intruders.push(mkIntruder("scout", 40, 20));
    if (gameOverCta) gameOverCta.hidden = true;
  }
  function mkIntruder(type, x, y, hardened) {
    var def = TYPES[type];
    return {
      type: type, x: x, y: y, w: def.w, h: def.h, hp: hardened ? def.hp + 1 : def.hp,
      speed: def.speed * waveSpeedMul, dir: "down", fireCd: 2 + Math.random(),
      erraticT: 0.5, hardened: !!hardened, telegraph: 0, flash: 0
    };
  }

  function startGame() {
    resetRun();
    state = STATE.PLAYING; stateT = 0; idleT = 0;
    startWave(0);
    if (gameOverCta) gameOverCta.hidden = true;
  }
  function togglePause() {
    if (state === STATE.PLAYING) { state = STATE.PAUSED; }
    else if (state === STATE.PAUSED && !pausedByVisibility) { state = STATE.PLAYING; }
  }

  // ---------------------------------------------------------------
  // Input
  // ---------------------------------------------------------------
  var canvasFocused = false;
  canvas.addEventListener("focus", function () { canvasFocused = true; hideOverlay(); });
  canvas.addEventListener("blur", function () { canvasFocused = false; });

  function hideOverlay() { if (overlayPrompt) overlayPrompt.hidden = true; }

  // Shared by the canvas itself AND the "CLICK OR TAP TO PLAY" overlay
  // button that sits on top of it before first focus: both must focus
  // the canvas AND actually start/restart the run in one gesture, or a
  // pointer user needs two separate clicks/taps to get into a game a
  // keyboard user starts with one Space press.
  function activatePointer(e) {
    if (e && e.cancelable) e.preventDefault();
    canvas.focus();
    firstGesture();
    if (state === STATE.ATTRACT) startGame();
    else if (state === STATE.GAME_OVER) enterAttract();
  }
  if (overlayPrompt) {
    overlayPrompt.addEventListener("click", activatePointer);
    overlayPrompt.addEventListener("touchstart", activatePointer, { passive: false });
  }

  function firstGesture() {
    ensureAudio();
    if (audioCtx && audioCtx.state === "suspended") audioCtx.resume();
  }

  function isTypingTarget(el) {
    if (!el) return false;
    var tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
  }

  window.addEventListener("keydown", function (e) {
    // The landing page's own pricing form has a real email <input>; a
    // global shortcut listener must not steal keystrokes ("m", "p", ...)
    // typed into it or any other field on the page.
    if (isTypingTarget(e.target)) return;
    var k = e.key;
    var isGameKey = ["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", " ", "Enter", "w", "a", "s", "d", "W", "A", "S", "D"].indexOf(k) !== -1;
    // A keyboard-only player who has never clicked/tapped the canvas
    // has no DOM focus on anything in particular — document.activeElement
    // is <body>, so e.target here is <body> too. Previously every branch
    // below was gated on canvasFocused, which is only ever set true by
    // the canvas's own "focus" event, which in turn only ever fired from
    // a pointer handler (activatePointer) — so Enter/Space/arrows did
    // nothing at all until the player clicked or tapped first, even
    // though the canvas is focusable (tabindex="0") and PRESS START is
    // on screen inviting exactly this. Route this one case through the
    // same canvas.focus() a real click takes (synchronous — its "focus"
    // listener flips canvasFocused and hides the overlay before the
    // next line runs) so a bare Enter/Space/arrow genuinely starts the
    // game. Anything with its own DOM focus (a link, a button, an
    // input — already excluded above) keeps its native key handling.
    if (!canvasFocused && isGameKey && e.target === document.body) {
      canvas.focus();
    }
    // Capture before the state-machine branches below run, not just
    // while PLAYING — ATTRACT/GAME_OVER/ENTER_INITIALS all act on this
    // same keydown (start, restart, initials entry), and a focused
    // canvas should never let Space/Arrow/Enter fall through to the
    // browser's native page scroll no matter which of those states it
    // is currently in.
    if (canvasFocused && isGameKey) e.preventDefault();
    firstGesture();
    if (k === "p" || k === "P" || k === "Escape") { togglePause(); return; }
    if (k === "m" || k === "M") { setMuted(!muted); return; }
    if (!canvasFocused) return;
    idleT = 0;
    if (state === STATE.ATTRACT && isGameKey) { startGame(); return; }
    if (state === STATE.GAME_OVER && isGameKey) { enterAttract(); return; }
    if (state === STATE.ENTER_INITIALS) { handleInitialsKey(k); return; }
    keysDown[k] = true;
    updateInputFromKeys();
  });
  window.addEventListener("keyup", function (e) {
    delete keysDown[e.key];
    updateInputFromKeys();
  });
  function updateInputFromKeys() {
    var up = keysDown["ArrowUp"] || keysDown["w"] || keysDown["W"];
    var down = keysDown["ArrowDown"] || keysDown["s"] || keysDown["S"];
    var left = keysDown["ArrowLeft"] || keysDown["a"] || keysDown["A"];
    var right = keysDown["ArrowRight"] || keysDown["d"] || keysDown["D"];
    input.up = !!up; input.down = !!down; input.left = !!left; input.right = !!right;
    input.fire = !!keysDown[" "];
    if (up) lastPressedDir = "up"; else if (down) lastPressedDir = "down";
    else if (left) lastPressedDir = "left"; else if (right) lastPressedDir = "right";
  }

  canvas.addEventListener("click", activatePointer);
  canvas.addEventListener("touchstart", activatePointer, { passive: false });

  function bindHold(el, dirKey) {
    if (!el) return;
    var set = function (v) {
      return function (e) {
        e.preventDefault();
        firstGesture();
        touchDirs[dirKey] = v;
        input[dirKey] = v || input[dirKey];
        recomputeTouch();
      };
    };
    el.addEventListener("touchstart", set(true), { passive: false });
    el.addEventListener("touchend", set(false), { passive: false });
    el.addEventListener("touchcancel", set(false), { passive: false });
    el.addEventListener("mousedown", set(true));
    el.addEventListener("mouseup", set(false));
    el.addEventListener("mouseleave", set(false));
  }
  function recomputeTouch() {
    input.up = touchDirs.up; input.down = touchDirs.down;
    input.left = touchDirs.left; input.right = touchDirs.right;
    if (touchDirs.up) lastPressedDir = "up"; else if (touchDirs.down) lastPressedDir = "down";
    else if (touchDirs.left) lastPressedDir = "left"; else if (touchDirs.right) lastPressedDir = "right";
    idleT = 0;
    if (state === STATE.ATTRACT) startGame();
  }
  if (dpad) {
    bindHold(dpad.querySelector(".d-up"), "up");
    bindHold(dpad.querySelector(".d-down"), "down");
    bindHold(dpad.querySelector(".d-left"), "left");
    bindHold(dpad.querySelector(".d-right"), "right");
  }
  if (fireBtn) {
    fireBtn.addEventListener("touchstart", function (e) {
      e.preventDefault(); firstGesture(); input.fire = true; idleT = 0;
      if (state === STATE.ATTRACT) startGame();
      else if (state === STATE.GAME_OVER) enterAttract();
    }, { passive: false });
    fireBtn.addEventListener("touchend", function (e) { e.preventDefault(); input.fire = false; }, { passive: false });
    fireBtn.addEventListener("mousedown", function () { input.fire = true; });
    fireBtn.addEventListener("mouseup", function () { input.fire = false; });
  }

  // Initial mute-button label only; the click is bound once, sitewide,
  // by site.js — which delegates to window.VaultDefenseAudio.toggle()
  // here when the game is on the page, so the button never gets two
  // competing listeners on the landing page.
  if (muteBtn) setMuted(muted);
  window.VaultDefenseAudio = {
    toggle: function () { firstGesture(); setMuted(!muted); },
    isMuted: function () { return muted; }
  };

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      if (state === STATE.PLAYING) { state = STATE.PAUSED; pausedByVisibility = true; }
      // The hi-score ticker's rotation timer has no other cleanup path;
      // stop it while the tab is hidden instead of leaving it ticking
      // against a text node nobody can see.
      if (tickerLine && tickerLine.__vdInterval) {
        clearInterval(tickerLine.__vdInterval);
        tickerLine.__vdInterval = null;
      }
    } else {
      if (state === STATE.PAUSED && pausedByVisibility) { pausedByVisibility = false; }
      refreshHiscoreDom();
    }
  });
  window.addEventListener("blur", function () {
    if (state === STATE.PLAYING) { state = STATE.PAUSED; pausedByVisibility = true; }
  });

  var running = true;
  if ("IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      running = entries[0].isIntersecting;
    }, { threshold: 0.01 });
    io.observe(canvas);
  }

  // ---------------------------------------------------------------
  // Initials entry
  // ---------------------------------------------------------------
  var initials = ["A", "A", "A"], initialsSlot = 0, pendingScore = 0;
  function handleInitialsKey(k) {
    var letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var idx = letters.indexOf(initials[initialsSlot]);
    if (k === "ArrowUp" || k === "w" || k === "W") initials[initialsSlot] = letters[(idx + 1) % 26];
    else if (k === "ArrowDown" || k === "s" || k === "S") initials[initialsSlot] = letters[(idx + 25) % 26];
    else if (k === "ArrowLeft" || k === "a" || k === "A") initialsSlot = Math.max(0, initialsSlot - 1);
    else if (k === "ArrowRight" || k === "d" || k === "D") initialsSlot = Math.min(2, initialsSlot + 1);
    else if (k === " ") {
      if (initialsSlot < 2) { initialsSlot++; }
      else { commitScore(); }
    }
  }
  function commitScore() {
    var arr = loadScores();
    arr.push({ initials: initials.join(""), score: pendingScore, wave: wave + 1, date: new Date().toISOString() });
    arr.sort(function (a, b) { return b.score - a.score; });
    arr = arr.slice(0, 10);
    saveScores(arr);
    hi = topScore();
    refreshHiscoreDom();
    enterAttract();
  }

  // ---------------------------------------------------------------
  // Fixed-timestep simulation
  // ---------------------------------------------------------------
  function tick(dt) {
    stateT += dt;
    if (hitstop > 0) { hitstop -= dt; return; }
    if (state === STATE.ATTRACT) { tickAttract(dt); return; }
    if (state !== STATE.PLAYING) return;
    idleT += dt;

    // (1) input -> velocity
    var speed = 90 * (dt);
    var moved = false;
    if (lastPressedDir === "up" && input.up) { player.y -= speed; player.dir = "up"; moved = true; }
    else if (lastPressedDir === "down" && input.down) { player.y += speed; player.dir = "down"; moved = true; }
    else if (lastPressedDir === "left" && input.left) { player.x -= speed; player.dir = "left"; moved = true; }
    else if (lastPressedDir === "right" && input.right) { player.x += speed; player.dir = "right"; moved = true; }
    else if (input.up) { player.y -= speed; player.dir = "up"; moved = true; }
    else if (input.down) { player.y += speed; player.dir = "down"; moved = true; }
    else if (input.left) { player.x -= speed; player.dir = "left"; moved = true; }
    else if (input.right) { player.x += speed; player.dir = "right"; moved = true; }
    clampToField(player);
    resolveWallCollision(player);
    if (moved) { player.treadT += dt; if (player.treadT > 0.12) { player.treadT = 0; player.tread = 1 - player.tread; } }
    if (player.invuln > 0) player.invuln -= dt;
    if (player.shieldT > 0) player.shieldT -= dt;

    // (2) fire
    if (player.cooldown > 0) player.cooldown -= dt;
    if (input.fire && player.cooldown <= 0) {
      spawnBullet(player.x + player.w / 2, player.y + player.h / 2, player.dir, true);
      player.cooldown = 0.3;
      sfxShot();
    }

    // (3) spawn queue
    spawnTimer -= dt;
    var cfg = waveConfig(wave);
    var liveCount = intruders.length;
    if (spawnQueue.length && liveCount < 6 && spawnTimer <= 0) {
      var t = spawnQueue.shift();
      var corner = pickSpawnX(cfg);
      var hardened = cfg.hardened && (t === "reader" || t === "shouter") && Math.random() < 0.3;
      intruders.push(mkIntruder(t, corner, 8, hardened));
      spawnTimer = cfg.interval;
    }

    // (4) intruder AI — iterate backward: breachVault() may splice the
    // current entry out of `intruders` mid-pass, and a forward forEach
    // would silently skip whatever shifts into that slot.
    for (var _ii = intruders.length - 1; _ii >= 0; _ii--) {
      updateIntruderAI(intruders[_ii], dt);
    }

    // (5) return fire handled inside AI tick above

    // (6) collisions
    updateBullets(dt);
    resolveCollisions();

    // (7) powerup timers
    powerups.forEach(function (p) { p.bobT = (p.bobT || 0) + dt; });

    // particles / pops / popups decay
    tickFx(dt);

    // (8) wave clear check
    if (spawnQueue.length === 0 && intruders.length === 0 && state === STATE.PLAYING) {
      onWaveClear();
    }

    if (shake > 0) shake -= dt;
  }

  function clampToField(e) {
    e.x = Math.max(0, Math.min(FIELD_W - e.w, e.x));
    e.y = Math.max(0, Math.min(FIELD_H - e.h, e.y));
  }
  function rectsOverlap(a, b) {
    return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;
  }
  function resolveWallCollision(e) {
    for (var i = 0; i < walls.length; i++) {
      var w = walls[i];
      if (rectsOverlap(e, w)) {
        var dx1 = (e.x + e.w) - w.x, dx2 = (w.x + w.w) - e.x;
        var dy1 = (e.y + e.h) - w.y, dy2 = (w.y + w.h) - e.y;
        var min = Math.min(dx1, dx2, dy1, dy2);
        if (min === dx1) e.x -= dx1; else if (min === dx2) e.x += dx2;
        else if (min === dy1) e.y -= dy1; else e.y += dy2;
      }
    }
  }

  function updateIntruderAI(iv, dt) {
    var def = TYPES[iv.type];
    var speed = def.speed * waveSpeedMul * dt;
    if (def.erratic) {
      iv.erraticT -= dt;
      if (iv.erraticT <= 0) {
        iv.erraticT = 0.5 + Math.random() * 0.1;
        if (Math.random() < 0.3) iv.randDir = Math.random() * Math.PI * 2;
        else iv.randDir = null;
      }
      if (iv.randDir != null) {
        iv.x += Math.cos(iv.randDir) * speed;
        iv.y += Math.sin(iv.randDir) * speed;
      } else {
        steerToVault(iv, speed);
      }
    } else if (def.fires) {
      steerToVault(iv, speed * 0.9);
      iv.fireCd -= dt;
      if (iv.fireCd <= 0.3 && iv.telegraph <= 0) iv.telegraph = 0.3;
      if (iv.telegraph > 0) {
        iv.telegraph -= dt;
        if (iv.telegraph <= 0 && iv.fireCd <= 0) {
          spawnBullet(iv.x + iv.w / 2, iv.y + iv.h / 2, dirToward(iv, player), false);
          iv.fireCd = iv.hardened ? 1.8 : 2.5;
        }
      }
    } else {
      steerToVault(iv, speed);
    }
    clampToField(iv);
    resolveWallCollision(iv);
    if (iv.flash > 0) { iv.flash -= dt; if (iv.flash < 0) iv.flash = 0; }
    if (rectsOverlap(iv, VAULT)) breachVault(iv);
  }
  function dirToward(from, to) {
    var dx = to.x - from.x, dy = to.y - from.y;
    if (Math.abs(dx) > Math.abs(dy)) return dx > 0 ? "right" : "left";
    return dy > 0 ? "down" : "up";
  }
  function steerToVault(iv, speed) {
    var tx = VAULT.x + VAULT.w / 2, ty = VAULT.y;
    var dx = tx - (iv.x + iv.w / 2), dy = ty - (iv.y + iv.h / 2);
    // Bias the heading toward "fall" rather than "turn" by weighting dy
    // before normalizing, not after: the old code normalized (dx,dy) to
    // a unit vector first and only THEN multiplied the y component by
    // 1.3, which does not renormalize — the resultant vector's magnitude
    // silently exceeds `speed` by up to 30% on a mostly-vertical
    // approach, so intruders moved measurably faster than the wave
    // table's `speed` said they should. Weighting dy first and
    // normalizing the biased vector keeps the true speed at exactly
    // `speed` while keeping the same "prefers falling" character.
    var by = dy * 1.3;
    var blen = Math.sqrt(dx * dx + by * by) || 1;
    iv.x += (dx / blen) * speed;
    iv.y += (by / blen) * speed;
    iv.dir = Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? "right" : "left") : (dy > 0 ? "down" : "up");
  }

  function spawnBullet(x, y, dir, isPlayer) {
    var vx = 0, vy = 0, sp = 220;
    if (dir === "up") vy = -sp; else if (dir === "down") vy = sp;
    else if (dir === "left") vx = -sp; else vx = sp;
    bullets.push({ x: x - 1, y: y - 2, w: 2, h: 4, vx: vx, vy: vy, isPlayer: isPlayer });
  }
  function updateBullets(dt) {
    for (var i = bullets.length - 1; i >= 0; i--) {
      var b = bullets[i];
      b.x += b.vx * dt; b.y += b.vy * dt;
      if (b.x < -4 || b.x > FIELD_W + 4 || b.y < -4 || b.y > FIELD_H + 4) { bullets.splice(i, 1); continue; }
      var hitWall = false;
      for (var w = 0; w < walls.length; w++) {
        if (rectsOverlap(b, walls[w])) {
          hitWall = true;
          if (walls[w].type === "brick") {
            walls[w].hp--;
            if (walls[w].hp <= 0) walls.splice(w, 1);
          }
          break;
        }
      }
      if (hitWall) { bullets.splice(i, 1); continue; }
    }
  }

  function resolveCollisions() {
    for (var i = bullets.length - 1; i >= 0; i--) {
      var b = bullets[i];
      if (!b) continue;
      if (b.isPlayer) {
        for (var j = intruders.length - 1; j >= 0; j--) {
          var iv = intruders[j];
          if (rectsOverlap(b, iv)) {
            bullets.splice(i, 1);
            hitstop = 0.033;
            iv.hp--;
            iv.flash = 0.08;
            sfxHit();
            debugEvent("bullet_hit", { type: iv.type, hpLeft: iv.hp });
            if (iv.hp <= 0) killIntruder(iv, j);
            break;
          }
        }
      } else if (player.alive && player.invuln <= 0 && player.shieldT <= 0 && rectsOverlap(b, player)) {
        bullets.splice(i, 1);
        hitstop = 0.033;
        playerHit();
      }
    }
    // powerup pickup
    for (var p = powerups.length - 1; p >= 0; p--) {
      if (rectsOverlap(player, powerups[p])) {
        applyPowerup(powerups[p]);
        powerups.splice(p, 1);
      }
    }
  }

  function killIntruder(iv, idx) {
    intruders.splice(idx, 1);
    var def = TYPES[iv.type];
    var base = def.score * (iv.hardened ? 1.5 : 1);
    if (comboT > 0) combo = Math.min(4, combo + 1); else combo = 1;
    comboT = 1.5;
    var pts = Math.round(base * combo);
    score += pts;
    debugEvent("kill", { type: iv.type, pts: pts, score: score });
    checkExtraLife();
    spawnParticles(iv.x + iv.w / 2, iv.y + iv.h / 2, PAL.red);
    spawnRedactedPop(iv.x + iv.w / 2, iv.y);
    popups.push({ text: "+" + pts + (combo > 1 ? " x" + combo : ""), t: 0, dur: 0.7,
      x: iv.x + iv.w / 2, y: iv.y, color: PAL.coin_yellow || PAL.yellow, floaty: true });
    sfxKill();
    maybeDropPowerup(iv);
    updateHudScore();
  }

  function checkExtraLife() {
    var nextThresh = score >= 20000 ? 20000 + Math.floor((score - 20000) / 50000) * 50000 : 20000;
    if (!player.__lifeMarks) player.__lifeMarks = 0;
    var earned = score >= 20000 ? 1 + Math.floor((score - 20000) / 50000) : 0;
    if (earned > player.__lifeMarks) {
      player.__lifeMarks = earned;
      if (lives < 5) { lives++; } else { score += 2000; }
    }
  }

  function maybeDropPowerup(iv) {
    if (powerups.length) return;
    var w = wave;
    if (w >= 3 && !dropGiven[wave + "_shield"]) {
      dropGiven[wave + "_shield"] = true;
      spawnPowerup("shield", iv.x, iv.y); return;
    }
    if (w >= 4 && !dropGiven[wave + "_barricade"]) {
      dropGiven[wave + "_barricade"] = true;
      spawnPowerup("barricade", iv.x, iv.y); return;
    }
    var r = Math.random();
    if (w >= 3 && r < 1 / 6) spawnPowerup("shield", iv.x, iv.y);
    else if (w >= 4 && r < 2 / 6) spawnPowerup("barricade", iv.x, iv.y);
    else if (r < 2.3 / 6 && !dropGiven[wave + "_manifest"]) { dropGiven[wave + "_manifest"] = true; spawnPowerup("manifest", iv.x, iv.y); }
  }
  function spawnPowerup(kind, x, y) {
    powerups.push({ kind: kind, x: x, y: y, w: 8, h: 8, bobT: 0 });
  }
  function applyPowerup(p) {
    sfxPowerup();
    if (p.kind === "shield") player.shieldT = 8;
    else if (p.kind === "barricade") { placeBrickRing(); }
    else if (p.kind === "manifest") { score += 500; updateHudScore(); }
  }

  function playerHit() {
    combo = 1; comboT = 0; perfectWave = false;
    spawnParticles(player.x + player.w / 2, player.y + player.h / 2, PAL.phosphor);
    lives--;
    updateHudLives();
    debugEvent("player_hit", { livesLeft: lives });
    shake = motionOK ? 0.18 : 0;
    if (lives <= 0) { onGameOver(); return; }
    player.x = FIELD_W / 2 - 8; player.y = FIELD_H - 24;
    player.invuln = 0.8;
  }

  function breachVault(iv) {
    var idx = intruders.indexOf(iv);
    if (idx >= 0) intruders.splice(idx, 1);
    perfectWave = false;
    vaultBreachT = 0.6;
    vaultBreachHandle = HANDLES[vaultLabelIdx % HANDLES.length];
    lives--;
    updateHudLives();
    debugEvent("vault_breach", { handle: vaultBreachHandle, livesLeft: lives });
    shake = motionOK ? 0.2 : 0;
    sfxBreach();
    if (lives <= 0) { onGameOver(); }
  }

  function spawnParticles(x, y, color) {
    var n = 4 + Math.floor(Math.random() * 5);
    for (var i = 0; i < n && particles.length < 150; i++) {
      var a = Math.random() * Math.PI * 2, sp = 20 + Math.random() * 40;
      particles.push({ x: x, y: y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp, t: 0, dur: 0.3 + Math.random() * 0.1, color: color });
    }
  }
  function spawnRedactedPop(x, y) {
    redPops.push({ x: x, y: y, t: 0, dur: 0.6 });
  }
  function tickFx(dt) {
    for (var i = particles.length - 1; i >= 0; i--) {
      var p = particles[i]; p.t += dt; p.x += p.vx * dt; p.y += p.vy * dt; p.vy += 60 * dt;
      if (p.t >= p.dur) particles.splice(i, 1);
    }
    for (var j = redPops.length - 1; j >= 0; j--) {
      redPops[j].t += dt; if (redPops[j].t >= redPops[j].dur) redPops.splice(j, 1);
    }
    for (var k = popups.length - 1; k >= 0; k--) {
      popups[k].t += dt; if (popups[k].t >= popups[k].dur) popups.splice(k, 1);
    }
    if (comboT > 0) { comboT -= dt; if (comboT <= 0) combo = 1; }
    vaultLabelT += dt;
    if (vaultLabelT > 3) { vaultLabelT = 0; vaultLabelIdx = (vaultLabelIdx + 1) % HANDLES.length; }
    if (vaultBreachT > 0) vaultBreachT -= dt;
  }

  function onWaveClear() {
    state = STATE.WAVE_CLEAR; stateT = 0;
    var bonus = 200 * (wave + 1);
    var perfect = perfectWave;
    debugEvent("wave_clear", { wave: wave, perfect: perfect });
    sfxWaveClear();
    setTimeout(function () {
      score += bonus;
      if (perfect) score += 1000;
      updateHudScore();
      var next = wave + 1;
      setTimeout(function () {
        if (state === STATE.WAVE_CLEAR) {
          state = STATE.PLAYING;
          startWave(next);
        }
      }, 900);
    }, 300);
    popups.push({ text: "WAVE CLEAR", t: 0, dur: 1.4, y: FIELD_H / 2 - 30, color: PAL.phosphor });
    if (perfectWave) popups.push({ text: "PERFECT — COMMAND POLICY HELD", t: 0, dur: 1.6, y: FIELD_H / 2 - 10, color: PAL.cyan });
  }

  function onGameOver() {
    state = STATE.GAME_OVER; stateT = 0;
    sfxGameOver();
    pendingScore = score;
    var scores = loadScores();
    var qualifies = scores.length < 10 || score > scores[scores.length - 1].score;
    updateHudLives();
    if (gameOverCta) gameOverCta.hidden = false;
    if (qualifies && score > 0) {
      setTimeout(function () {
        // A player can mash a game-key within this delay to bounce
        // GAME_OVER -> ATTRACT -> PLAYING (a fresh run) before this
        // fires; only claim the state if we're still on the GAME_OVER
        // screen this timeout was scheduled for.
        if (state === STATE.GAME_OVER) {
          state = STATE.ENTER_INITIALS; initials = ["A", "A", "A"]; initialsSlot = 0;
        }
      }, 1600);
    }
  }

  function tickAttract(dt) {
    idleT += dt;
    var sc = attractScript;
    sc.t += dt;
    // ~8s scripted beats, phase-driven so array splices never re-gate
    // the branch that should run next (see prior bug: gating phase 2's
    // movement on `intruders.length < 1` made it dead code the moment
    // the demo intruder was actually pushed).
    if (sc.phase === 0) {
      if (intruders[0]) intruders[0].y += 30 * dt;
      if (sc.t >= 3 && intruders[0]) {
        spawnParticles(intruders[0].x + 7, intruders[0].y + 7, PAL.red);
        spawnRedactedPop(intruders[0].x + 7, intruders[0].y);
        intruders.shift();
        sc.phase = 1;
      }
    } else if (sc.phase === 1) {
      if (sc.t >= 4 && !sc.spawned2) {
        sc.spawned2 = true;
        intruders.push(mkIntruder("scout", FIELD_W - 24, 8));
      }
      if (sc.spawned2 && intruders[0]) {
        var iv = intruders[0];
        iv.y += 34 * dt;
        iv.x += (VAULT.x + 8 - iv.x) * 0.4 * dt;
        if (iv.y > VAULT.y - 4) {
          vaultBreachT = 0.6;
          vaultBreachHandle = HANDLES[0];
          shake = motionOK ? 0.15 : 0;
          sfxBreach();
          intruders.shift();
          sc.phase = 2;
        }
      }
    }
    tickFx(dt);
    if (sc.t >= sc.total) {
      attractScript = buildAttractScript();
      player.x = 40; player.y = FIELD_H - 60;
      intruders = [mkIntruder("scout", 40, 20)];
    }
  }

  // ---------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------
  function render() {
    ctx.fillStyle = PAL.void_;
    ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);

    ctx.save();
    if (shake > 0 && motionOK) {
      ctx.translate((Math.random() - 0.5) * 8, (Math.random() - 0.5) * 8);
    }
    ctx.translate(0, 16); // HUD strip offset

    // Vault
    drawVault();
    // walls
    walls.forEach(function (w) {
      var name = w.type === "steel" ? "steelWall" : (w.hp === 1 ? "brick2" : "brick1");
      drawSpriteRotated(name, w.x + 8, w.y + 8, 0);
    });
    // powerups
    powerups.forEach(function (p) {
      var bob = motionOK ? Math.sin(p.bobT * 4) * 2 : 0;
      var name = p.kind === "shield" ? "shieldIcon" : p.kind === "barricade" ? "barricadeIcon" : "manifestIcon";
      drawSpriteRotated(name, p.x + 4, p.y + 4 + bob, 0);
    });
    // intruders
    intruders.forEach(function (iv) {
      var name = iv.type + (iv.hardened ? "Hard" : "");
      if (!cache[name]) name = iv.type;
      var angle = DIR_ANGLE[iv.dir] || 0;
      drawSpriteRotated(name, iv.x + iv.w / 2, iv.y + iv.h / 2, angle, iv.flash > 0);
      if (iv.type === "shouter" && iv.telegraph > 0) {
        ctx.fillStyle = PAL.cyan;
        ctx.fillRect(iv.x + iv.w - 4, iv.y - 2, 4, 4);
      }
      if (iv.type === "saboteur" && motionOK) {
        ctx.globalAlpha = 0.35;
        ctx.strokeStyle = PAL.cyan;
        ctx.strokeRect(iv.x - 1, iv.y - 1, iv.w + 2, iv.h + 2);
        ctx.globalAlpha = 1;
      }
    });
    // player
    if (state === STATE.PLAYING || state === STATE.PAUSED || state === STATE.WAVE_CLEAR) {
      var blinkOn = player.invuln > 0 ? (Math.floor(stateT * 8) % 2 === 0) : true;
      if (blinkOn) {
        var pname = player.tread ? "playerB" : "playerA";
        drawSpriteRotated(pname, player.x + 8, player.y + 8, DIR_ANGLE[player.dir]);
        if (player.shieldT > 0) {
          ctx.strokeStyle = PAL.cyan;
          ctx.lineWidth = 1;
          ctx.strokeRect(player.x - 2, player.y - 2, player.w + 4, player.h + 4);
        }
      }
    } else if (state === STATE.ATTRACT) {
      drawSpriteRotated(player.tread ? "playerB" : "playerA", player.x + 8, player.y + 8, DIR_ANGLE[player.dir] || 0);
    }
    // bullets
    ctx.fillStyle = PAL.phosphor;
    bullets.forEach(function (b) {
      ctx.fillStyle = b.isPlayer ? PAL.phosphor : PAL.red;
      ctx.fillRect(b.x, b.y, b.w, b.h);
    });
    // particles
    particles.forEach(function (p) {
      ctx.globalAlpha = Math.max(0, 1 - p.t / p.dur);
      ctx.fillStyle = p.color;
      ctx.fillRect(p.x, p.y, 2, 2);
      ctx.globalAlpha = 1;
    });
    // redacted pops
    ctx.font = "8px 'Press Start 2P', monospace";
    ctx.textAlign = "center";
    redPops.forEach(function (r) {
      var prog = r.t / r.dur;
      var dy = motionOK ? -20 * Math.min(1, prog * 1.4) : 0;
      ctx.globalAlpha = Math.max(0, 1 - prog);
      ctx.fillStyle = "#000";
      ctx.fillRect(r.x - 34, r.y - 10 + dy, 68, 12);
      ctx.fillStyle = PAL.yellow;
      ctx.fillText("[REDACTED]", r.x, r.y - 1 + dy);
      ctx.globalAlpha = 1;
    });
    // score popups
    popups.forEach(function (p) {
      var prog = p.t / p.dur;
      ctx.globalAlpha = Math.max(0, 1 - prog);
      ctx.fillStyle = p.color || PAL.phosphor;
      ctx.font = "8px 'Press Start 2P', monospace";
      if (p.floaty) {
        var dy = motionOK ? -16 * prog : 0;
        ctx.fillText(p.text, p.x, p.y + dy);
      } else {
        ctx.fillText(p.text, FIELD_W / 2, p.y);
      }
      ctx.globalAlpha = 1;
    });
    ctx.restore();

    drawTopStrip();
    drawStateOverlay();
  }

  function drawVault() {
    var inverted = vaultBreachT > 0;
    var steps = Math.floor((0.6 - Math.max(0, vaultBreachT)) / 0.15) % 2 === 0;
    ctx.fillStyle = inverted && (!motionOK || steps) ? PAL.phosphor : PAL.steel;
    ctx.fillRect(VAULT.x, VAULT.y, VAULT.w, VAULT.h);
    ctx.fillStyle = inverted && (!motionOK || steps) ? PAL.void_ : PAL.trackDark;
    ctx.fillRect(VAULT.x + 4, VAULT.y + 4, VAULT.w - 8, VAULT.h - 8);
    ctx.font = "6px 'Press Start 2P', monospace";
    ctx.textAlign = "center";
    ctx.fillStyle = vaultBreachT > 0 ? PAL.red : PAL.cyan;
    var label = vaultBreachT > 0 ? "[REDACTED:" + vaultBreachHandle + "]" : HANDLES[vaultLabelIdx % HANDLES.length];
    ctx.save();
    ctx.font = vaultBreachT > 0 ? "5px 'Press Start 2P', monospace" : "6px 'Press Start 2P', monospace";
    ctx.fillText(label, VAULT.x + VAULT.w / 2, VAULT.y + VAULT.h / 2 + 2);
    ctx.restore();
  }

  function drawTopStrip() {
    ctx.fillStyle = PAL.void_;
    ctx.fillRect(0, 0, CANVAS_W, 16);
    if (combo > 1 && comboT > 0) {
      ctx.font = "8px 'Press Start 2P', monospace";
      ctx.fillStyle = PAL.yellow;
      ctx.textAlign = "left";
      ctx.fillText("x" + combo, 4, 12);
    }
  }

  function drawStateOverlay() {
    ctx.textAlign = "center";
    ctx.font = "8px 'Press Start 2P', monospace";
    if (state === STATE.ATTRACT) {
      var showPrompt = motionOK ? (Math.floor(stateT * 2) % 2 === 0) : true;
      if (showPrompt) {
        ctx.fillStyle = PAL.yellow;
        var coarse = false;
        try { coarse = window.matchMedia("(pointer: coarse)").matches; } catch (e) {}
        ctx.fillText(coarse ? "TAP TO PLAY" : "PRESS START", CANVAS_W / 2, CANVAS_H - 20);
      }
    } else if (state === STATE.PAUSED) {
      dimBox();
      ctx.fillStyle = PAL.phosphor;
      ctx.fillText("PAUSED", CANVAS_W / 2, CANVAS_H / 2);
    } else if (state === STATE.GAME_OVER || state === STATE.ENTER_INITIALS) {
      dimBox();
      var blink = motionOK ? (Math.floor(stateT * 4) % 2 === 0) : true;
      if (blink) { ctx.fillStyle = PAL.red; ctx.fillText("GAME OVER", CANVAS_W / 2, CANVAS_H / 2 - 30); }
      ctx.fillStyle = PAL.text_hi || "#e8f3ea";
      ctx.font = "6px 'Press Start 2P', monospace";
      ctx.fillText("SCORE " + pad(score, 6) + "   WAVE " + (wave + 1), CANVAS_W / 2, CANVAS_H / 2 - 12);
      if (state === STATE.ENTER_INITIALS) {
        ctx.font = "8px 'Press Start 2P', monospace";
        ctx.fillStyle = PAL.yellow;
        ctx.fillText("ENTER YOUR INITIALS", CANVAS_W / 2, CANVAS_H / 2 + 8);
        var s = "";
        for (var i = 0; i < 3; i++) s += (i === initialsSlot && Math.floor(stateT * 4) % 2 === 0) ? "_" : initials[i];
        ctx.font = "10px 'Press Start 2P', monospace";
        ctx.fillStyle = PAL.phosphor;
        ctx.fillText(s.split("").join(" "), CANVAS_W / 2, CANVAS_H / 2 + 26);
      } else {
        ctx.font = "6px 'Press Start 2P', monospace";
        ctx.fillStyle = PAL.cyan;
        ctx.fillText("CLICK / TAP TO CONTINUE", CANVAS_W / 2, CANVAS_H / 2 + 30);
      }
    }
  }
  function dimBox() {
    ctx.fillStyle = "rgba(10,14,10,0.65)";
    ctx.fillRect(0, 16, FIELD_W, FIELD_H);
  }
  function pad(n, len) {
    var s = String(Math.floor(n));
    while (s.length < len) s = "0" + s;
    return s;
  }

  // ---------------------------------------------------------------
  // HUD (DOM)
  // ---------------------------------------------------------------
  function updateHudScore() {
    if (hudScore) hudScore.textContent = pad(score, 6);
    if (score > hi) { hi = score; if (hudHi) hudHi.textContent = pad(hi, 6); }
    try {
      window.dispatchEvent(new CustomEvent("vaultdefense:score", { detail: { score: score } }));
    } catch (e) { /* CustomEvent unsupported: mobile install bar just won't show a live score */ }
  }
  function updateHudLives() {
    if (!hudLives) return;
    hudLives.innerHTML = "";
    for (var i = 0; i < 5; i++) {
      var span = document.createElement("span");
      span.className = "life-icon" + (i < lives ? "" : " lost");
      hudLives.appendChild(span);
    }
  }
  function updateHudWave() { if (hudWave) hudWave.textContent = String(wave + 1); }

  function refreshHiscoreDom() {
    if (hudHi) hudHi.textContent = pad(hi, 6);
    var scores = loadScores();
    if (tickerLine) {
      if (!scores.length) {
        tickerLine.textContent = "HI-SCORE " + pad(0, 6);
      } else {
        var top5 = scores.slice(0, 5);
        var i = 0;
        var render2 = function () {
          var e = top5[i % top5.length];
          tickerLine.textContent = "HI-SCORE " + pad(e.score, 6) + "  " + e.initials;
          i++;
        };
        render2();
        if (top5.length > 1 && !tickerLine.__vdInterval) {
          tickerLine.__vdInterval = setInterval(render2, 6000);
        }
      }
    }
    var tbody = document.getElementById("hiscore-table-body");
    if (tbody) {
      tbody.innerHTML = "";
      if (!scores.length) {
        var tr = document.createElement("tr");
        tr.innerHTML = '<td colspan="4">NO SCORES YET — BE THE FIRST</td>';
        tbody.appendChild(tr);
      } else {
        scores.slice(0, 10).forEach(function (e, idx) {
          var row = document.createElement("tr");
          row.innerHTML = "<td>" + (idx + 1) + "</td><td>" + escapeHtml(e.initials) +
            "</td><td>" + e.wave + "</td><td class=\"score\">" + pad(e.score, 6) + "</td>";
          tbody.appendChild(row);
        });
      }
    }
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // ---------------------------------------------------------------
  // Main loop
  // ---------------------------------------------------------------
  var acc = 0, last = null;
  function frame(ts) {
    requestAnimationFrame(frame);
    if (!running) { last = null; return; }
    if (last == null) last = ts;
    var delta = ts - last;
    last = ts;
    if (delta > 250) delta = 250;
    acc += delta;
    var steps = 0;
    while (acc >= STEP_MS && steps < MAX_CATCHUP) {
      tick(STEP_MS / 1000);
      acc -= STEP_MS;
      steps++;
    }
    if (steps === MAX_CATCHUP) acc = 0;
    updateHudWave();
    render();
  }

  // ---------------------------------------------------------------
  // Canvas scaling
  // ---------------------------------------------------------------
  function rescale() {
    var frameEl = canvas.parentElement;
    var availW = frameEl ? frameEl.clientWidth : window.innerWidth;
    // 0.7/560, not the old 0.6/520: that cap sat just below the 512px
    // (2x CANVAS_H) a common ~850px-tall desktop window needs, so once
    // the hard "always at least 2x" floor below is (correctly) removed
    // for mobile's sake, ordinary desktop windows were sliding down to
    // 1x too — this keeps 2x reachable on desktop while still leaving
    // width (not height) as the real limiter on narrow phones.
    var availH = Math.min(window.innerHeight * 0.7, 560);
    var scale = Math.floor(Math.min(availW / CANVAS_W, availH / CANVAS_H));
    // Floor of 1, not 2: forcing a minimum of 2x (480px wide) regardless
    // of how little width the cabinet actually has is what pushed the
    // canvas past the viewport edge on phones under ~480px of available
    // width — nearly all phones in portrait. 1x (240px) always fits.
    scale = Math.max(1, Math.min(4, scale || 1));
    canvas.style.width = CANVAS_W * scale + "px";
    canvas.style.height = CANVAS_H * scale + "px";
  }
  window.addEventListener("resize", rescale);
  window.addEventListener("orientationchange", rescale);
  rescale();

  canvas.width = CANVAS_W;
  canvas.height = CANVAS_H;

  // ---------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------
  var booted = false;
  function boot() {
    if (booted) return;
    booted = true;
    refreshHiscoreDom();
    updateHudScore();
    updateHudLives();
    updateHudWave();
    enterAttract();
    requestAnimationFrame(frame);
  }
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(boot).catch(boot);
    setTimeout(boot, 800); // never block first frame indefinitely if fonts stall
  } else {
    boot();
  }
})();
