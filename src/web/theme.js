// Color theme and day/night mode, kept in this browser (localStorage).
// Loaded in the head and not deferred: the choice is written on the root
// element before the page is drawn, so a page never shows first in the
// wrong colors. Without this script the stylesheet follows the system
// setting by itself, and the two controls stay hidden.
(function () {
  "use strict";
  var THEME = "vulnizard-theme";
  var MODE = "vulnizard-mode";
  var root = document.documentElement;
  var system = window.matchMedia("(prefers-color-scheme: dark)");

  // Storage may be refused (private browsing, policy): the choice then lasts for the page
  var memory = {};
  function read(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return memory[key] || null; }
  }
  function write(key, value) {
    memory[key] = value;
    try {
      if (value === null) window.localStorage.removeItem(key); else window.localStorage.setItem(key, value);
    } catch (e) { /* kept in memory */ }
  }

  function systemMode() { return system.matches ? "dark" : "light"; }

  // No stored mode: the system setting decides, and keeps deciding when it changes
  function mode() {
    var stored = read(MODE);
    return stored === "light" || stored === "dark" ? stored : systemMode();
  }

  // The value comes from storage: only a plain name ever reaches the page
  function theme() {
    var stored = read(THEME);
    return stored && /^[a-z]{1,20}$/.test(stored) ? stored : "classic";
  }

  function apply() {
    root.setAttribute("data-mode", mode());
    root.setAttribute("data-theme", theme());
    var select = document.querySelector("[data-theme-choice]");
    if (select) {
      select.value = theme();
      // A theme this version no longer has: back to the first of the list
      if (select.selectedIndex < 0) {
        select.selectedIndex = 0;
        root.setAttribute("data-theme", select.value);
      }
    }
    var toggle = document.querySelector("[data-mode-toggle]");
    if (toggle) toggle.setAttribute("aria-pressed", mode() === "dark" ? "true" : "false");
  }

  root.classList.add("js");
  apply();

  document.addEventListener("DOMContentLoaded", apply);
  document.addEventListener("change", function (event) {
    var target = event.target;
    if (!target || !target.matches || !target.matches("[data-theme-choice]")) return;
    write(THEME, target.value === "classic" ? null : target.value);
    apply();
  });
  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || !target.closest || !target.closest("[data-mode-toggle]")) return;
    var wanted = mode() === "dark" ? "light" : "dark";
    // Choosing what the system already asks for is going back to following it
    write(MODE, wanted === systemMode() ? null : wanted);
    apply();
  });
  // The system switches (sunset), or another tab changed the choice
  if (system.addEventListener) system.addEventListener("change", apply);
  window.addEventListener("storage", apply);
})();
