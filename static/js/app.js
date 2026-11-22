/* NexiVault front-end behaviour. No inline scripts are used (strict Content-Security-Policy). */
(function () {
  "use strict";
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = csrfMeta ? csrfMeta.content : "";

  // ---------------------------------------------------------------- toasts
  var ICONS = {
    success: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    danger: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
  };
  var stack = document.getElementById("toasts");

  function dismiss(toast) {
    toast.classList.add("leaving");
    setTimeout(function () { toast.remove(); }, 250);
  }
  function arm(toast) {
    var timer = setTimeout(function () { dismiss(toast); }, toast.classList.contains("danger") ? 8000 : 5000);
    toast.addEventListener("mouseenter", function () { clearTimeout(timer); });
  }
  function toast(message, type) {
    if (!stack) return;
    type = type || "success";
    var el = document.createElement("div");
    el.className = "toast " + type;
    el.setAttribute("role", "status");
    var icon = document.createElement("span");
    icon.className = "toast-icon";
    icon.innerHTML = ICONS[type === "danger" ? "danger" : "success"];
    var text = document.createElement("span");
    text.className = "toast-text";
    text.textContent = message;               // textContent: never interpret messages as HTML
    var close = document.createElement("button");
    close.type = "button"; close.className = "toast-close"; close.setAttribute("aria-label", "Dismiss");
    close.textContent = "×";
    el.append(icon, text, close);
    stack.appendChild(el);
    arm(el);
  }
  if (stack) {
    stack.querySelectorAll(".toast").forEach(arm);
    stack.addEventListener("click", function (e) {
      var btn = e.target.closest(".toast-close");
      if (btn) dismiss(btn.closest(".toast"));
    });
  }

  // ---------------------------------------------------------------- helpers
  function postJSON(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": CSRF, "X-Requested-With": "XMLHttpRequest" },
      credentials: "same-origin",
      body: JSON.stringify(body || {})
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.status === 401 && data.locked) { window.location.href = "/unlock"; }
        if (!res.ok) throw new Error(data.error || "Something went wrong.");
        return data;
      });
    });
  }
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext !== false) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {          // fallback for plain http on some browsers
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); } catch (err) { reject(err); }
      ta.remove();
    });
  }
  function updateMeter(meter, result, hasValue) {
    if (!meter) return;
    meter.className = meter.className.replace(/\blvl-\S+/g, "").trim() + " lvl-" + (hasValue ? result.score : "none");
    var label = meter.querySelector(".meter-label");
    if (label) label.textContent = hasValue ? result.label : "Enter a password";
  }

  // ---------------------------------------------------------------- sidebar (mobile)
  var shell = document.querySelector(".app-shell");
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-sidebar-open]")) shell.classList.add("sidebar-open");
    if (e.target.closest("[data-sidebar-close]")) shell.classList.remove("sidebar-open");
  });

  // ---------------------------------------------------------------- confirm dialog + loading state
  var dialog = document.getElementById("confirm-dialog");
  var pendingForm = null;
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (e.defaultPrevented) return;
    if (form.dataset.confirm && dialog && typeof dialog.showModal === "function" && !form.dataset.confirmed) {
      e.preventDefault();
      pendingForm = form;
      document.getElementById("confirm-title").textContent = form.dataset.confirmTitle || "Are you sure?";
      document.getElementById("confirm-text").textContent = form.dataset.confirm;
      dialog.showModal();
      return;
    }
    if (form.dataset.confirm && !dialog) return;
    if (form.method.toLowerCase() === "post" && !form.hasAttribute("data-no-loading")) {
      var btn = form.querySelector('button[type="submit"], button:not([type])');
      if (btn) { btn.classList.add("is-loading"); setTimeout(function () { btn.disabled = true; }, 0); }
    }
  });
  if (dialog) {
    dialog.addEventListener("close", function () {
      if (dialog.returnValue === "ok" && pendingForm) {
        pendingForm.dataset.confirmed = "1";
        pendingForm.requestSubmit ? pendingForm.requestSubmit() : pendingForm.submit();
      }
      dialog.returnValue = "";
      pendingForm = null;
    });
    dialog.addEventListener("click", function (e) { if (e.target === dialog) dialog.close("cancel"); });
  }
  window.addEventListener("pageshow", function () {   // restore buttons when using the browser Back button
    document.querySelectorAll(".is-loading").forEach(function (b) { b.classList.remove("is-loading"); b.disabled = false; });
    document.querySelectorAll("form[data-confirmed]").forEach(function (f) { delete f.dataset.confirmed; });
  });

  // ---------------------------------------------------------------- click actions
  document.addEventListener("click", function (e) {
    // Show / hide a password input
    var toggle = e.target.closest("[data-toggle]");
    if (toggle) {
      var input = document.getElementById(toggle.dataset.toggle);
      if (input) {
        var show = input.type === "password";
        input.type = show ? "text" : "password";
        toggle.classList.toggle("is-visible", show);
      }
      return;
    }

    // Copy the value of a read-only field (generator)
    var copyBtn = e.target.closest("[data-copy-target]");
    if (copyBtn) {
      var field = document.getElementById(copyBtn.dataset.copyTarget);
      if (!field || !field.value) { toast("Generate a password first.", "danger"); return; }
      copyText(field.value).then(function () {
        var label = copyBtn.querySelector("span");
        toast("Copied to clipboard.");
        if (label) { label.textContent = "Copied!"; setTimeout(function () { label.textContent = "Copy"; }, 1500); }
      }, function () { toast("Couldn't copy. Select the text and copy it manually.", "danger"); });
      return;
    }

    // Reveal a saved password inside its row (auto-hides after 20 seconds)
    var reveal = e.target.closest("[data-reveal-url]");
    if (reveal) {
      var row = reveal.closest(".vault-row");
      var secret = row && row.querySelector("[data-secret]");
      if (!secret) return;
      if (reveal.classList.contains("is-visible")) { hideSecret(reveal, secret); return; }
      reveal.disabled = true;
      postJSON(reveal.dataset.revealUrl).then(function (data) {
        secret.textContent = data.password;
        secret.classList.add("revealed");
        reveal.classList.add("is-visible");
        clearTimeout(reveal._timer);
        reveal._timer = setTimeout(function () { hideSecret(reveal, secret); }, 20000);
      }).catch(function (err) { toast(err.message, "danger"); })
        .then(function () { reveal.disabled = false; });
      return;
    }

    // Copy a saved password straight from the row
    var copyRow = e.target.closest("[data-copy-url]");
    if (copyRow) {
      copyRow.disabled = true;
      postJSON(copyRow.dataset.copyUrl)
        .then(function (data) { return copyText(data.password); })
        .then(function () { toast("Password copied to clipboard."); })
        .catch(function (err) { toast(err && err.message ? err.message : "Couldn't copy the password.", "danger"); })
        .then(function () { copyRow.disabled = false; });
      return;
    }

    // Generate a password into a form field
    var gen = e.target.closest("[data-generate-into]");
    if (gen) {
      var target = document.getElementById(gen.dataset.generateInto);
      gen.disabled = true;
      postJSON("/generator/api", { length: 20, upper: true, lower: true, digits: true, symbols: true })
        .then(function (data) {
          target.value = data.password;
          target.type = "text";
          var eye = document.querySelector('[data-toggle="' + target.id + '"]');
          if (eye) eye.classList.add("is-visible");
          target.dispatchEvent(new Event("input", { bubbles: true }));
          toast("Strong password generated.");
        })
        .catch(function (err) { toast(err.message, "danger"); })
        .then(function () { gen.disabled = false; });
    }
  });

  function hideSecret(btn, secret) {
    clearTimeout(btn._timer);
    secret.textContent = "••••••••••";
    secret.classList.remove("revealed");
    btn.classList.remove("is-visible");
  }

  // ---------------------------------------------------------------- live strength meters
  document.querySelectorAll("[data-strength-input]").forEach(function (input) {
    var meter = document.getElementById(input.dataset.strengthInput);
    function refresh() { updateMeter(meter, window.NVStrength.evaluate(input.value), !!input.value); }
    input.addEventListener("input", refresh);
    refresh();
  });

  // ---------------------------------------------------------------- auto-submit filters
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form.submit(); });
  });

  // ---------------------------------------------------------------- generator page
  var genForm = document.getElementById("generator-form");
  if (genForm) {
    var out = document.getElementById("generated-password");
    var wrap = document.getElementById("generated-wrap");
    var meter = document.getElementById("gen-strength");
    var length = document.getElementById("length");
    var lengthOut = document.getElementById(length.dataset.rangeOutput);
    var boxes = genForm.querySelectorAll('input[type="checkbox"]');
    var debounce;

    function options() {
      return { length: parseInt(length.value, 10), upper: genForm.upper.checked, lower: genForm.lower.checked,
               digits: genForm.digits.checked, symbols: genForm.symbols.checked };
    }
    function generate() {
      wrap.classList.add("is-loading");
      postJSON(genForm.dataset.generatorApi, options()).then(function (data) {
        out.value = data.password;
        updateMeter(meter, data.strength, true);
      }).catch(function (err) { toast(err.message, "danger"); })
        .then(function () { wrap.classList.remove("is-loading"); });
    }
    genForm.addEventListener("submit", function (e) { e.preventDefault(); generate(); });
    length.addEventListener("input", function () {
      lengthOut.textContent = length.value;
      clearTimeout(debounce); debounce = setTimeout(generate, 250);
    });
    boxes.forEach(function (box) {
      box.addEventListener("change", function () {
        if (!Array.prototype.some.call(boxes, function (b) { return b.checked; })) {
          box.checked = true;
          toast("Select at least one character type.", "danger");
          return;
        }
        generate();
      });
    });
    generate();                                   // show a fresh password on page load
  }
  document.querySelectorAll("[data-range-output]").forEach(function (r) {
    var o = document.getElementById(r.dataset.rangeOutput);
    r.addEventListener("input", function () { if (o) o.textContent = r.value; });
  });
})();
