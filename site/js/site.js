/* ClaudePass site-wide behavior: header mute/CRT toggles, terminal
 * copy buttons, and the landing page's scroll-aware mobile install
 * bar. Loaded on every page; the game engine (site/game/game.js) is
 * loaded only on the landing page and is a separate, larger file so
 * inner pages never download it.
 *
 * No inline scripts anywhere in site/ — this file, plus game.js on
 * the landing page, are the only two script sources the CSP allows.
 */
(function () {
  "use strict";

  var LS_MUTED = "vaultdefense.muted";
  var LS_CRT = "vaultdefense.crt";

  function lsGet(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function lsSet(key, val) {
    try { window.localStorage.setItem(key, val); } catch (e) { /* ignore */ }
  }

  // ---------------------------------------------------------------
  // Mute toggle — delegates to the game engine's real AudioContext
  // when it's on the page (window.VaultDefenseAudio, set by game.js);
  // otherwise this is just a preference for a future visit.
  // ---------------------------------------------------------------
  var muteBtn = document.getElementById("mute-toggle");
  function paintMuteBtn(v) {
    if (!muteBtn) return;
    muteBtn.setAttribute("aria-pressed", v ? "false" : "true");
    muteBtn.textContent = v ? "🔇" : "🔊";
    muteBtn.setAttribute("aria-label", v ? "Unmute sound" : "Mute sound");
  }
  if (muteBtn) {
    if (!window.VaultDefenseAudio) paintMuteBtn(lsGet(LS_MUTED) !== "0");
    muteBtn.addEventListener("click", function () {
      if (window.VaultDefenseAudio) {
        window.VaultDefenseAudio.toggle();
        return;
      }
      var next = lsGet(LS_MUTED) === "0"; // was unmuted -> mute; was muted/unset -> unmute
      lsSet(LS_MUTED, next ? "1" : "0");
      paintMuteBtn(next);
    });
  }

  // ---------------------------------------------------------------
  // CRT scanline toggle — one localStorage key, two entry points
  // (header icon + footer text), every .crt-overlay on the page.
  // ---------------------------------------------------------------
  var crtOn = lsGet(LS_CRT) !== "0";
  function paintCrt(v) {
    var overlays = document.querySelectorAll(".crt-overlay");
    for (var i = 0; i < overlays.length; i++) overlays[i].hidden = !v;
    var iconBtn = document.getElementById("crt-toggle");
    if (iconBtn) iconBtn.setAttribute("aria-pressed", v ? "true" : "false");
    var textBtn = document.getElementById("crt-text-toggle");
    if (textBtn) textBtn.textContent = "CRT: " + (v ? "ON" : "OFF");
  }
  function setCrt(v) {
    crtOn = v;
    lsSet(LS_CRT, v ? "1" : "0");
    paintCrt(v);
  }
  paintCrt(crtOn);
  var crtIconBtn = document.getElementById("crt-toggle");
  var crtTextBtn = document.getElementById("crt-text-toggle");
  if (crtIconBtn) crtIconBtn.addEventListener("click", function () { setCrt(!crtOn); });
  if (crtTextBtn) crtTextBtn.addEventListener("click", function () { setCrt(!crtOn); });

  // ---------------------------------------------------------------
  // Terminal copy buttons (Install page, and anywhere else a
  // .terminal-line ships one). Pure progressive enhancement: with
  // this script absent the command is still a plain, selectable
  // <code> block with no button.
  // ---------------------------------------------------------------
  var copyBtns = document.querySelectorAll(".copy-btn");
  for (var c = 0; c < copyBtns.length; c++) {
    (function (btn) {
      var line = btn.closest(".terminal-line");
      var codeEl = line ? line.querySelector("code") : null;
      if (!codeEl) return;
      btn.addEventListener("click", function () {
        var text = codeEl.textContent;
        var done = function () {
          var original = "COPY";
          btn.textContent = "COPIED";
          setTimeout(function () { btn.textContent = original; }, 1200);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, done);
        } else {
          try {
            var range = document.createRange();
            range.selectNodeContents(codeEl);
            var sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            document.execCommand("copy");
            sel.removeAllRanges();
          } catch (e) { /* selection copy unsupported; button still labels itself */ }
          done();
        }
      });
    })(copyBtns[c]);
  }

  // ---------------------------------------------------------------
  // Email field error state (pricing's optional Pro email, account's
  // required reissue email). HTML5 constraint validation only —
  // type="email" already treats an empty non-required field as
  // valid, so this covers both "must be a real address if given" and
  // "must be present and a real address". Registered before the
  // Checkout Hand-off listener below on the same form element so an
  // invalid address stops the submit (and the spinner/redirect state)
  // via stopImmediatePropagation instead of racing it.
  // ---------------------------------------------------------------
  var emailValidatedForms = document.querySelectorAll("form.checkout-form");
  for (var ef = 0; ef < emailValidatedForms.length; ef++) {
    (function (form) {
      var input = form.querySelector('input[type="email"]');
      if (!input) return;
      function clearError() {
        input.removeAttribute("aria-invalid");
        input.classList.remove("is-error");
      }
      function showError() {
        input.setAttribute("aria-invalid", "true");
        input.classList.add("is-error");
      }
      input.addEventListener("input", function () {
        if (input.validity.valid) clearError();
      });
      form.addEventListener("submit", function (e) {
        if (!input.validity.valid) {
          e.preventDefault();
          e.stopImmediatePropagation();
          showError();
          input.focus();
          return;
        }
        clearError();
      });
    })(emailValidatedForms[ef]);
  }

  // ---------------------------------------------------------------
  // Checkout hand-off state (CLA-32 "Checkout Hand-off — Redirecting").
  // Scoped to the real Stripe Checkout POST (action="/checkout"), not
  // every form sharing the .checkout-form layout class (the /account
  // reissue form also uses it, and "TAKING YOU TO SECURE CHECKOUT"
  // would be the wrong label there). Plain form POST, no fetch/AJAX —
  // the swapped label only needs to hold until the browser navigates
  // away to Stripe.
  // ---------------------------------------------------------------
  var checkoutForms = document.querySelectorAll('form.checkout-form[action="/checkout"]');
  for (var cf = 0; cf < checkoutForms.length; cf++) {
    (function (form) {
      form.addEventListener("submit", function () {
        if (form.classList.contains("is-submitting")) return;
        var btn = form.querySelector('button[type="submit"]');
        form.classList.add("is-submitting");
        if (btn) {
          btn.disabled = true;
          btn.innerHTML = '<span class="spinner spinner-inline" aria-hidden="true"></span> TAKING YOU TO SECURE CHECKOUT…';
        }
      });
    })(checkoutForms[cf]);
  }

  // ---------------------------------------------------------------
  // Command Policy alert dismiss control (.cp-alert "✕" — /security).
  // ---------------------------------------------------------------
  var cpDismissBtns = document.querySelectorAll(".cp-alert-dismiss");
  for (var cd = 0; cd < cpDismissBtns.length; cd++) {
    (function (btn) {
      btn.addEventListener("click", function () {
        var alertEl = btn.closest(".cp-alert");
        if (alertEl) alertEl.hidden = true;
      });
    })(cpDismissBtns[cd]);
  }

  // ---------------------------------------------------------------
  // Scroll-aware mobile install bar (landing page only, under 720px
  // — CSS also gates visibility, this just drives the class + copy).
  // ---------------------------------------------------------------
  var bar = document.getElementById("mobile-install-bar");
  var cabinet = document.querySelector(".cabinet");
  if (bar && cabinet && "IntersectionObserver" in window) {
    var barScore = document.getElementById("mobile-bar-score");
    var lastScore = 0;
    window.addEventListener("vaultdefense:score", function (e) {
      lastScore = (e.detail && e.detail.score) || 0;
      if (barScore) barScore.textContent = lastScore > 0 ? "SCORE " + pad(lastScore, 6) : "";
    });
    function pad(n, len) {
      var s = String(Math.floor(n));
      while (s.length < len) s = "0" + s;
      return s;
    }
    var io = new IntersectionObserver(function (entries) {
      var cabinetVisible = entries[0].isIntersecting;
      if (cabinetVisible) bar.classList.remove("is-visible");
      else bar.classList.add("is-visible");
    }, { threshold: 0 });
    io.observe(cabinet);
  }
})();
