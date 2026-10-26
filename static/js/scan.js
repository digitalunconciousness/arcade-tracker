/* Scan page: read a cabinet label with the phone's camera.
 *
 * The page works without this script (a USB scanner or the keyboard types into the box).
 * When a code is read it goes into that same box and the form is submitted, so the server
 * does the resolving exactly as for a typed code: /scan?code= sends it to /g/<id>.
 *
 * The panel says which box (data-camera-input, default "code") and what then happens
 * (data-camera-then: "submit", the default, or the id of a field to focus, as count mode
 * does so the count can be typed).
 *
 * Decoding: the browser's own BarcodeDetector where it has one (Chrome on Android), else the
 * bundled jsQR (static/js/vendor), loaded the first time it is needed. Browsers only give a
 * page the camera over https, so on a plain-http address the button explains that instead.
 */
(function () {
  "use strict";

  var panel = document.querySelector("[data-camera]");
  if (!panel) return;
  var box = document.getElementById(panel.dataset.cameraInput || "code");
  var form = box.form;
  var then = panel.dataset.cameraThen || "submit";
  var start = panel.querySelector("[data-camera-start]");
  var stop = panel.querySelector("[data-camera-stop]");
  var view = panel.querySelector(".scan-camera__view");
  var video = panel.querySelector("video");
  var status = panel.querySelector("[data-camera-status]");
  var canvas = document.createElement("canvas");
  var context = canvas.getContext("2d", { willReadFrequently: true });
  var stream = null;
  var timer = null;
  var detector = null;
  var MAX_SIDE = 640;   // frames are scaled down to this before jsQR reads them
  var EVERY_MS = 150;

  function say(text) { status.textContent = text; }

  if (!window.isSecureContext || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    panel.hidden = false;
    start.disabled = true;
    say("The camera only works on the https:// address of the tracker.");
    return;
  }
  panel.hidden = false;

  // A phone has no USB scanner; don't open its keyboard over the camera button. Autofocus
  // lands after this script runs, so wait for the page to finish loading.
  if (window.matchMedia("(pointer: coarse)").matches) {
    window.addEventListener("load", function () {
      window.setTimeout(function () { if (document.activeElement === box) box.blur(); }, 0);
    });
  }

  function loadJsQR() {
    if (window.jsQR) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      var s = document.createElement("script");
      s.src = panel.dataset.jsqr;
      s.onload = resolve;
      s.onerror = function () { reject(new Error("jsQR")); };
      document.head.appendChild(s);
    });
  }

  function chooseDecoder() {
    if ("BarcodeDetector" in window && window.BarcodeDetector.getSupportedFormats) {
      return window.BarcodeDetector.getSupportedFormats().then(function (formats) {
        if (formats.indexOf("qr_code") !== -1) {
          detector = new window.BarcodeDetector({ formats: ["qr_code"] });
          return;
        }
        return loadJsQR();
      }, loadJsQR);
    }
    return loadJsQR();
  }

  function decode() {
    if (video.readyState < 2) return Promise.resolve(null);
    if (detector) {
      return detector.detect(video).then(function (codes) {
        return codes.length ? codes[0].rawValue : null;
      }, function () { return null; });
    }
    var scale = Math.min(1, MAX_SIDE / Math.max(video.videoWidth, video.videoHeight));
    canvas.width = Math.round(video.videoWidth * scale);
    canvas.height = Math.round(video.videoHeight * scale);
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    var frame = context.getImageData(0, 0, canvas.width, canvas.height);
    var code = window.jsQR(frame.data, frame.width, frame.height, { inversionAttempts: "dontInvert" });
    return Promise.resolve(code ? code.data : null);
  }

  function tick() {
    decode().then(function (text) {
      if (!stream) return;
      text = (text || "").trim();
      if (text) {
        finish();
        say("Read " + text);
        box.value = text;
        if (then === "submit") {
          form.requestSubmit ? form.requestSubmit() : form.submit();
        } else {
          var next = document.getElementById(then);
          if (next) next.focus();
        }
        return;
      }
      timer = window.setTimeout(tick, EVERY_MS);
    });
  }

  function finish() {
    window.clearTimeout(timer);
    timer = null;
    if (stream) stream.getTracks().forEach(function (t) { t.stop(); });
    stream = null;
    video.srcObject = null;
    view.hidden = true;
    stop.hidden = true;
    start.hidden = false;
  }

  start.addEventListener("click", function () {
    start.disabled = true;
    say("Starting the camera…");
    chooseDecoder()
      .then(function () {
        return navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: "environment" } }, audio: false
        });
      })
      .then(function (s) {
        stream = s;
        video.srcObject = s;
        view.hidden = false;
        start.hidden = true;
        stop.hidden = false;
        say("Point the camera at the label's QR code.");
        return video.play();
      })
      .then(tick)
      .catch(function (err) {
        finish();
        if (err && (err.name === "NotAllowedError" || err.name === "SecurityError")) {
          say("The browser was not allowed to use the camera. Allow it in the site settings and try again.");
        } else if (err && err.name === "NotFoundError") {
          say("No camera was found on this device.");
        } else if (err && err.message === "jsQR") {
          say("The scanner could not load. Reload the page and try again.");
        } else {
          say("The camera could not start" + (err && err.name ? " (" + err.name + ")." : "."));
        }
      })
      .then(function () { start.disabled = false; });
  });

  stop.addEventListener("click", function () { finish(); say(""); });
  // Leaving the page, or switching apps, lets go of the camera.
  window.addEventListener("pagehide", finish);
  document.addEventListener("visibilitychange", function () {
    if (document.hidden && stream) { finish(); say(""); }
  });
})();
