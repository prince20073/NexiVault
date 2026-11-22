/* Password strength estimate. Mirrors password_strength() in security.py - keep both in sync. */
(function () {
  var COMMON = ["password", "passw0rd", "123456", "12345678", "123456789", "1234567890", "qwerty", "qwertyuiop",
    "abc123", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "football", "baseball", "login",
    "master", "sunshine", "princess", "shadow", "superman", "trustno1", "whatever", "changeme", "secret",
    "default", "111111", "000000", "asdfgh", "zxcvbn", "starwars", "hello"];
  var LEET = { "@": "a", "4": "a", "0": "o", "1": "l", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t" };
  var WORD_PLUS_SUFFIX = /^[^A-Za-z]{0,3}[A-Za-z]{3,10}[^A-Za-z]{0,6}$/u;
  function leet(text) { return Array.from(text).map(function (c) { return LEET[c] || c; }).join(""); }
  var LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

  function sequenceRuns(chars) {
    var runs = 0, i = 0, n = chars.length;
    while (i < n - 3) {
      var step = chars[i + 1].codePointAt(0) - chars[i].codePointAt(0);
      if (step === 0 || step === 1 || step === -1) {
        var j = i + 1;
        while (j < n && chars[j].codePointAt(0) - chars[j - 1].codePointAt(0) === step) j++;
        if (j - i >= 4) { runs++; i = j; continue; }
      }
      i++;
    }
    return runs;
  }

  function evaluate(password) {
    if (!password) return { score: 0, label: LABELS[0], bits: 0 };
    var chars = Array.from(password);
    var pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 33;
    var unique = new Set(chars).size;
    var effective = unique + 0.3 * (chars.length - unique);
    var bits = effective * Math.log2(Math.max(pool, 2));
    bits -= 6 * Math.min(sequenceRuns(chars), 3);
    var lower = password.toLowerCase();
    var base = lower.replace(/[0-9!@#$%^&*()\-_=+.?]+$/, "");
    if (COMMON.indexOf(lower) !== -1 || COMMON.indexOf(base) !== -1 ||
        COMMON.indexOf(leet(lower)) !== -1 || COMMON.indexOf(leet(base)) !== -1) bits = Math.min(bits, 10);
    else if (WORD_PLUS_SUFFIX.test(password)) bits = Math.min(bits, 35);
    bits = Math.max(Math.trunc(bits), 0);
    var score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { score: score, label: LABELS[score], bits: bits };
  }

  window.NVStrength = { evaluate: evaluate };
})();
