/* Arcade Tracker UI behaviour. No framework, no build step, no inline handlers.
 *
 *   - registers the service worker (offline icons and CSS only; it never sees a page);
 *   - marks <html class="js"> so CSS can hide the phone menu only when this script runs
 *     (without it, the nav simply stays open);
 *   - the phone menu toggle;
 *   - dismissible banners;
 *   - select-all checkboxes (data-select-all="name", or a data-group) with a live count;
 *   - <form data-confirm="Question?" data-confirm-action="Delete">: a styled confirm dialog
 *     before submitting, falling back to window.confirm where <dialog> is missing;
 *   - <button data-print>: opens the print dialog (label sheets);
 *   - <input data-keep-focus>: the scan box takes focus back after a click elsewhere, so
 *     every scan lands in it;
 *   - <table data-sortable>: headings marked data-sort sort the rows when clicked.
 */
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  // Offline icons and stylesheets for the home-screen app (static/service-worker.js).
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
      navigator.serviceWorker.register("/static/service-worker.js").catch(function () {});
    });
  }

  function onReady(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  onReady(function () {
    // --- phone menu -----------------------------------------------------------------
    var toggle = document.querySelector(".menu-toggle");
    var nav = toggle && document.getElementById(toggle.getAttribute("aria-controls"));
    if (toggle && nav) {
      toggle.addEventListener("click", function () {
        var open = toggle.getAttribute("aria-expanded") !== "true";
        toggle.setAttribute("aria-expanded", String(open));
        if (open) nav.setAttribute("data-open", "");
        else nav.removeAttribute("data-open");
      });
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
          toggle.click();
          toggle.focus();
        }
      });
    }

    // --- dismissible banners ----------------------------------------------------------
    document.addEventListener("click", function (e) {
      var close = e.target.closest(".banner__close");
      if (close) close.closest(".banner").remove();
    });

    // --- select-all checkboxes: <input data-select-all="name"> and a live count -----
    // A box belongs to a select-all by its name, or by data-group when two lists share a name.
    function boxesFor(name) {
      return document.querySelectorAll('input[type=checkbox][name="' + name + '"]:not([data-group]),' +
                                        ' input[type=checkbox][data-group="' + name + '"]');
    }
    function syncCount(name) {
      var boxes = boxesFor(name);
      var n = Array.prototype.filter.call(boxes, function (b) { return b.checked; }).length;
      document.querySelectorAll('[data-selected-count="' + name + '"]').forEach(function (el) {
        el.textContent = n + " selected";
      });
      document.querySelectorAll('[data-select-all="' + name + '"]').forEach(function (all) {
        all.checked = n > 0 && n === boxes.length;
        all.indeterminate = n > 0 && n < boxes.length;
      });
    }
    document.addEventListener("change", function (e) {
      var t = e.target;
      if (t.matches("[data-select-all]")) {
        var name = t.getAttribute("data-select-all");
        boxesFor(name).forEach(function (b) {
          b.checked = t.checked;
        });
        syncCount(name);
      } else if (t.matches("input[type=checkbox][name]")) {
        var group = t.getAttribute("data-group") || t.name;
        if (document.querySelector('[data-select-all="' + group + '"]')) syncCount(group);
      }
    });

    // --- keep the scan box focused --------------------------------------------------------
    // Not on a touch screen: there it would open the keyboard on every tap.
    var keep = document.querySelector("[data-keep-focus]");
    if (keep && !window.matchMedia("(pointer: coarse)").matches) {
      document.addEventListener("click", function (e) {
        if (!e.target.closest("a, button, input, select, textarea, label, summary")) keep.focus();
      });
    }

    // --- sortable tables -----------------------------------------------------------------
    // <table data-sortable> with <th data-sort="text|num">: the heading becomes a button.
    // A cell sorts by its data-sort-value when it has one (days as a number, a date as ISO),
    // otherwise by its text. Without this script the table simply stays in server order.
    document.querySelectorAll("table[data-sortable]").forEach(function (table) {
      var heads = table.querySelectorAll("th[data-sort]");
      heads.forEach(function (th) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "sort";
        while (th.firstChild) button.appendChild(th.firstChild);
        th.appendChild(button);
        button.addEventListener("click", function () {
          var col = Array.prototype.indexOf.call(th.parentNode.children, th);
          var asc = th.getAttribute("aria-sort") !== "ascending";
          var numeric = th.getAttribute("data-sort") === "num";
          heads.forEach(function (h) { h.removeAttribute("aria-sort"); });
          th.setAttribute("aria-sort", asc ? "ascending" : "descending");
          var body = table.tBodies[0];
          var rows = Array.prototype.slice.call(body.rows);
          function key(row) {
            var cell = row.cells[col];
            var v = cell.hasAttribute("data-sort-value") ? cell.getAttribute("data-sort-value")
                                                          : cell.textContent.trim();
            return numeric ? parseFloat(v) || 0 : v.toLowerCase();
          }
          rows.sort(function (a, b) {
            var x = key(a), y = key(b);
            return (x < y ? -1 : x > y ? 1 : 0) * (asc ? 1 : -1);
          });
          rows.forEach(function (r) { body.appendChild(r); });
        });
      });
    });

    // --- print buttons ------------------------------------------------------------------
    document.addEventListener("click", function (e) {
      if (e.target.closest("[data-print]")) window.print();
    });

    // --- confirm before submitting a destructive form --------------------------------
    var dialog = document.getElementById("confirm-dialog");
    document.addEventListener("submit", function (e) {
      var form = e.target;
      if (!form.matches("form[data-confirm]") || form.dataset.confirmed === "1") return;
      e.preventDefault();
      var question = form.dataset.confirm;
      if (!dialog || typeof dialog.showModal !== "function") {
        if (window.confirm(question)) submit(form, e.submitter);
        return;
      }
      dialog.querySelector(".dialog__text").textContent = question;
      dialog.querySelector("[value=confirm]").textContent = form.dataset.confirmAction || "Confirm";
      dialog.returnValue = "";
      dialog.showModal();
      dialog.addEventListener("close", function handler() {
        dialog.removeEventListener("close", handler);
        if (dialog.returnValue === "confirm") submit(form, e.submitter);
      });
    });

    function submit(form, submitter) {
      form.dataset.confirmed = "1";
      if (form.requestSubmit) form.requestSubmit(submitter || undefined);
      else form.submit();
    }
  });
})();
