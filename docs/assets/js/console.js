/* Security Console — progressive enhancement only.
   The site is fully readable with JS disabled; this adds the scan-reveal
   choreography and the hero terminal "type-out" without blocking content. */
(function () {
  "use strict";

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---- scroll reveal ---------------------------------------------------- */
  function initReveal() {
    var els = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
    if (reduceMotion || !("IntersectionObserver" in window)) {
      els.forEach(function (el) { el.classList.add("is-visible"); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          e.target.classList.add("is-visible");
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });
    els.forEach(function (el) { io.observe(el); });
  }

  /* ---- hero terminal type-out ------------------------------------------ */
  /* Lines are authored in the DOM (so they're SEO/no-JS visible); JS hides
     then re-reveals them one character class at a time for the scan effect. */
  function initTypeout() {
    var term = document.querySelector("[data-typeout]");
    if (!term) return;
    var lines = Array.prototype.slice.call(term.querySelectorAll("[data-line]"));
    var cursor = term.querySelector(".cursor");

    if (reduceMotion) {
      lines.forEach(function (l) { l.style.visibility = "visible"; });
      if (cursor) cursor.style.display = "inline-block";
      return;
    }

    lines.forEach(function (l) { l.style.visibility = "hidden"; });
    if (cursor) cursor.style.display = "none";

    var i = 0;
    function next() {
      if (i >= lines.length) {
        if (cursor) { cursor.style.display = "inline-block"; lines[lines.length - 1].appendChild(cursor); }
        return;
      }
      var line = lines[i];
      line.style.visibility = "visible";
      // small per-line delay; instruction-like lines feel "executed"
      var delay = parseInt(line.getAttribute("data-delay") || "320", 10);
      i++;
      window.setTimeout(next, delay);
    }
    // kick off when the hero is on screen
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries, obs) {
        if (entries[0].isIntersecting) { next(); obs.disconnect(); }
      }, { threshold: 0.3 });
      io.observe(term);
    } else {
      next();
    }
  }

  /* ---- active-section nav highlight ------------------------------------ */
  function initNav() {
    var links = Array.prototype.slice.call(document.querySelectorAll("[data-navlink]"));
    if (!links.length || !("IntersectionObserver" in window)) return;
    var map = {};
    links.forEach(function (a) {
      var id = a.getAttribute("href");
      if (id && id.charAt(0) === "#") map[id.slice(1)] = a;
    });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        var a = map[e.target.id];
        if (!a) return;
        if (e.isIntersecting) {
          links.forEach(function (l) { l.removeAttribute("aria-current"); });
          a.setAttribute("aria-current", "true");
        }
      });
    }, { threshold: 0.5 });
    Object.keys(map).forEach(function (id) {
      var sec = document.getElementById(id);
      if (sec) io.observe(sec);
    });
  }

  /* ---- copy-to-clipboard for install commands -------------------------- */
  function initCopy() {
    document.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-copy");
        if (navigator.clipboard) {
          navigator.clipboard.writeText(text).then(function () {
            var prev = btn.textContent;
            btn.textContent = "copied ✓";
            window.setTimeout(function () { btn.textContent = prev; }, 1400);
          });
        }
      });
    });
  }

  function boot() {
    initReveal();
    initTypeout();
    initNav();
    initCopy();
    var y = document.querySelector("[data-year]");
    if (y) y.textContent = String(new Date().getFullYear());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
