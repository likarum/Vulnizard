// Live filters: typing in a filter form updates the list without submitting.
// The server stays the one that filters (same result as the "Filter" button);
// the form keeps working without JavaScript.
(function () {
  "use strict";
  var DELAY = 250;
  var sequence = 0;

  function urlOf(form) {
    var params = new URLSearchParams();
    new FormData(form).forEach(function (value, key) {
      if (typeof value === "string" && value !== "") params.append(key, value);
    });
    var query = params.toString();
    return form.getAttribute("action") + (query ? "?" + query : "");
  }

  function swap(form, html, url) {
    var fresh = new DOMParser().parseFromString(html, "text/html");
    var main = document.querySelector("main");
    var freshMain = fresh.querySelector("main");
    if (!main || !freshMain) { window.location.assign(url); return; }
    var index = Array.prototype.indexOf.call(main.querySelectorAll("form.filters"), form);
    var freshForm = freshMain.querySelectorAll("form.filters")[index];
    if (!freshForm) { window.location.assign(url); return; }

    // The form being typed in is kept as it is; only its status (count, "Clear") is refreshed
    var status = form.querySelector(".filter-status");
    var freshStatus = freshForm.querySelector(".filter-status");
    if (status && freshStatus) status.replaceWith(document.importNode(freshStatus, true));

    var active = document.activeElement;
    var caret = null;
    try { caret = active && form.contains(active) ? [active.selectionStart, active.selectionEnd] : null; } catch (e) { caret = null; }
    freshForm.replaceWith(form);
    main.replaceChildren.apply(main, Array.prototype.slice.call(freshMain.childNodes).map(function (node) {
      return node === form ? form : document.importNode(node, true);
    }));
    if (active && form.contains(active)) {
      active.focus();
      try { if (caret && caret[0] !== null) active.setSelectionRange(caret[0], caret[1]); } catch (e) { /* not a text field */ }
    }
    window.history.replaceState(null, "", url);
    bind();
  }

  function refresh(form) {
    var mine = ++sequence;
    var url = urlOf(form);
    fetch(url, { credentials: "same-origin", headers: { "X-Requested-With": "live-filter" } })
      .then(function (response) {
        if (!response.ok || response.redirected) { window.location.assign(url); return null; }
        return response.text();
      })
      .then(function (html) {
        // A newer keystroke is on its way: this answer is already out of date
        if (html !== null && mine === sequence) swap(form, html, url);
      })
      .catch(function () { /* offline: the Filter button still works */ });
  }

  function watch(form) {
    if (form.dataset.live) return;
    form.dataset.live = "1";
    var timer = null;
    var later = function () {
      clearTimeout(timer);
      timer = setTimeout(function () { refresh(form); }, DELAY);
    };
    form.addEventListener("input", later);
    form.addEventListener("change", later);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      clearTimeout(timer);
      refresh(form);
    });
  }

  // On a phone a table is shown as one card per row (app.css): each cell is
  // given the name of its column, which the header no longer shows there.
  function label(table) {
    var names = Array.prototype.map.call(table.querySelectorAll("thead th"), function (th) {
      return th.textContent.replace(/[\u25B2\u25BC]/g, "").trim();
    });
    Array.prototype.forEach.call(table.querySelectorAll("tbody tr"), function (row) {
      // A row spanning columns (an empty list) has no column to be named after
      if (row.cells.length !== names.length) return;
      Array.prototype.forEach.call(row.cells, function (cell, index) {
        if (names[index]) cell.setAttribute("data-label", names[index]);
      });
    });
  }

  // A toolbar acting on the checked rows of its form (data-selection names the
  // checkboxes) is greyed out while none is checked. The page is served with
  // the toolbar usable: without this script the server refuses an empty selection.
  function selection(toolbar) {
    var form = toolbar.closest("form");
    if (!form) return;
    var boxes = form.querySelectorAll('input[type="checkbox"][name="' + toolbar.getAttribute("data-selection") + '"]');
    var checked = Array.prototype.filter.call(boxes, function (box) { return box.checked; }).length;
    Array.prototype.forEach.call(toolbar.querySelectorAll("select, button, input"), function (control) {
      control.disabled = checked === 0;
    });
    var count = toolbar.querySelector(".selection-count");
    if (count) count.textContent = checked === 0 ? "Check users in the list first" : checked + " selected";
  }

  function selections() {
    Array.prototype.forEach.call(document.querySelectorAll("main [data-selection]"), selection);
  }

  function bind() {
    Array.prototype.forEach.call(document.querySelectorAll("main form.filters"), watch);
    Array.prototype.forEach.call(document.querySelectorAll("main table.list"), label);
    selections();
  }

  document.addEventListener("change", function (event) {
    if (event.target && event.target.type === "checkbox") selections();
  });
  // Coming back with the browser's Back button restores the checked boxes after the script ran
  window.addEventListener("pageshow", selections);

  bind();
})();
