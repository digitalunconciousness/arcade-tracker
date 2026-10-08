/* Arcade Tracker UI behaviour. No framework, no build step, no inline handlers.
 *
 *   - marks <html class="js"> so CSS can hide the phone menu only when this script runs
 *     (without it, the nav simply stays open);
 *   - the phone menu toggle;
 *   - dismissible banners;
 *   - <form data-confirm="Question?" data-confirm-action="Delete">: a styled confirm dialog
 *     before submitting, falling back to window.confirm where <dialog> is missing.
 */
(function () {
  "use strict";
  document.documentElement.classList.add("js");

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
