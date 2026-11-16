// Usability helpers only. Nothing here is a security control: every rule
// is enforced again on the server, because this file runs on a device the
// user (or an attacker) fully controls. No inline script is used anywhere,
// which lets the Content-Security-Policy forbid it.
(function () {
  "use strict";

  // Show / hide password (ASVS 6.2.6) -- fewer typos means fewer lockouts.
  document.querySelectorAll("[data-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.toggle);
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-pressed", String(show));
    });
  });

  // Early feedback on uploads so students are not surprised after waiting.
  document.querySelectorAll("form.upload").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      var file = form.querySelector("input[type=file]").files[0];
      var err = form.querySelector(".field-error");
      var msg = "";
      if (!file) msg = "Choose a file before submitting.";
      else if (!/\.(pdf|docx)$/i.test(file.name)) msg = "Only PDF (.pdf) and Word (.docx) files are accepted.";
      else if (file.size > Number(form.dataset.max)) msg = "That file is larger than the 10 MB limit.";
      err.textContent = msg;
      err.hidden = !msg;
      if (msg) e.preventDefault();
    });
  });

  // Character counter.
  document.querySelectorAll("[data-count]").forEach(function (area) {
    var out = document.getElementById(area.dataset.count);
    var update = function () { out.textContent = area.value.length; };
    area.addEventListener("input", update);
    update();
  });

  // Password length feedback (length is what matters, not symbols).
  document.querySelectorAll("[data-meter]").forEach(function (input) {
    var out = document.getElementById(input.dataset.meter);
    var min = Number(input.dataset.min);
    input.addEventListener("input", function () {
      var n = input.value.length;
      out.textContent = n === 0 ? "" : n < min ? (min - n) + " more character" + (min - n === 1 ? "" : "s") + " needed."
        : n < 16 ? "Good length." : "Strong length.";
    });
  });

  // Ask for the password only when the email address is being changed.
  var profile = document.querySelector("form[data-email]");
  if (profile) {
    var reauth = document.getElementById("reauth");
    var email = profile.querySelector("#email");
    var sync = function () {
      if (email.value.trim().toLowerCase() !== profile.dataset.email.toLowerCase()) reauth.removeAttribute("data-optional");
    };
    email.addEventListener("input", sync);
    sync();
  }

  // Inactivity warning: tell the user before the server signs them out,
  // and offer one clear action. The timeout itself is enforced server-side.
  var idle = Number(document.body.dataset.idle || 0);
  if (idle) {
    var WARN = 120;
    var box = document.getElementById("idle-warning");
    var left = document.getElementById("idle-left");
    var deadline = Date.now() + idle * 1000;
    setInterval(function () {
      var remaining = Math.round((deadline - Date.now()) / 1000);
      if (remaining <= 0) { window.location.assign(document.body.dataset.login); return; }
      if (remaining <= WARN) {
        left.textContent = remaining > 60 ? "2 minutes" : remaining + " seconds";
        if (box.hidden) { box.hidden = false; document.getElementById("idle-stay").focus(); }
      }
    }, 1000);
    document.getElementById("idle-stay").addEventListener("click", function () {
      fetch(document.body.dataset.keepalive, {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": document.body.dataset.csrf }
      }).then(function (r) {
        if (r.status === 204) { deadline = Date.now() + idle * 1000; box.hidden = true; }
        else window.location.assign(document.body.dataset.login);
      });
    });
  }
})();
