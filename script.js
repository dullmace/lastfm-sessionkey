// MD5 hashing function
function md5(str) {
  function md5cycle(x, k) {
    var a = x[0],
      b = x[1],
      c = x[2],
      d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936);
    d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819);
    b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897);
    d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341);
    b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416);
    d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063);
    b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682);
    d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290);
    b = ff(b, c, d, a, k[15], 22, 1236535329);
    a = gg(a, b, c, d, k[1], 5, -165796510);
    d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713);
    b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691);
    d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335);
    b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438);
    d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961);
    b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467);
    d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473);
    b = gg(b, c, d, a, k[12], 20, -1926607734);
    a = hh(a, b, c, d, k[5], 4, -378558);
    d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562);
    b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060);
    d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632);
    b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174);
    d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979);
    b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487);
    d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520);
    b = hh(b, c, d, a, k[2], 23, -995338651);
    a = ii(a, b, c, d, k[0], 6, -198630844);
    d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905);
    b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571);
    d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523);
    b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359);
    d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380);
    b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070);
    d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259);
    b = ii(b, c, d, a, k[9], 21, -343485551);
    x[0] = add32(a, x[0]);
    x[1] = add32(b, x[1]);
    x[2] = add32(c, x[2]);
    x[3] = add32(d, x[3]);
  }
  function cmn(q, a, b, x, s, t) {
    a = add32(add32(a, q), add32(x, t));
    return add32((a << s) | (a >>> (32 - s)), b);
  }
  function ff(a, b, c, d, x, s, t) {
    return cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function gg(a, b, c, d, x, s, t) {
    return cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function hh(a, b, c, d, x, s, t) {
    return cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function ii(a, b, c, d, x, s, t) {
    return cmn(c ^ (b | ~d), a, b, x, s, t);
  }
  function md51(s) {
    var n = s.length,
      state = [1732584193, -271733879, -1732584194, 271733878],
      i;
    for (i = 64; i <= s.length; i += 64) {
      md5cycle(state, md5blk(s.substring(i - 64, i)));
    }
    s = s.substring(i - 64);
    var tail = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    for (i = 0; i < s.length; i++)
      tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
    tail[i >> 2] |= 0x80 << ((i % 4) << 3);
    if (i > 55) {
      md5cycle(state, tail);
      for (i = 0; i < 16; i++) tail[i] = 0;
    }
    tail[14] = n * 8;
    md5cycle(state, tail);
    return state;
  }
  function md5blk(s) {
    var md5blks = [],
      i;
    for (i = 0; i < 64; i += 4) {
      md5blks[i >> 2] =
        s.charCodeAt(i) +
        (s.charCodeAt(i + 1) << 8) +
        (s.charCodeAt(i + 2) << 16) +
        (s.charCodeAt(i + 3) << 24);
    }
    return md5blks;
  }
  function rhex(n) {
    var hex_chr = "0123456789abcdef".split("");
    var s = "",
      j = 0;
    for (; j < 4; j++)
      s += hex_chr[(n >> (j * 8 + 4)) & 0x0f] + hex_chr[(n >> (j * 8)) & 0x0f];
    return s;
  }
  function hex(x) {
    for (var i = 0; i < x.length; i++) x[i] = rhex(x[i]);
    return x.join("");
  }
  function add32(a, b) {
    return (a + b) & 0xffffffff;
  }
  return hex(md51(str));
}

// ——— UI elements ———

const authorizeBtn = document.getElementById("authorizeBtn");
const apiKeyInput = document.getElementById("apiKey");
const sharedSecretInput = document.getElementById("sharedSecret");
const resultDiv = document.getElementById("result");
const errorDiv = document.getElementById("error");
const loadingDiv = document.getElementById("loading");
const sessionKeyOutput = document.getElementById("sessionKeyOutput");
const copyBtn = document.getElementById("copyBtn");
const resetBtn = document.getElementById("resetBtn");
const toggleSecretBtn = document.getElementById("toggleSecret");

function showError(message) {
  errorDiv.textContent = message;
  errorDiv.style.display = "block";
  resultDiv.style.display = "none";
}

function showSuccess(sessionKey) {
  sessionKeyOutput.textContent = sessionKey;
  resultDiv.style.display = "block";
  errorDiv.style.display = "none";
  window.history.replaceState({}, document.title, window.location.pathname);
}

function setLoading(isLoading) {
  loadingDiv.style.display = isLoading ? "block" : "none";
  authorizeBtn.disabled = isLoading;
}

window.addEventListener("load", async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get("token");

  if (token) {
    const apiKey = localStorage.getItem("lastfm_api_key");
    const sharedSecret = localStorage.getItem("lastfm_shared_secret");

    if (apiKey && sharedSecret) {
      await getSessionKey(apiKey, sharedSecret, token);
    } else {
      showError("Missing API credentials. Please start over.");
    }
  }
});

authorizeBtn.addEventListener("click", () => {
  const apiKey = apiKeyInput.value.trim();
  const sharedSecret = sharedSecretInput.value.trim();

  document.getElementById("apiKeyError").textContent = "";
  document.getElementById("secretError").textContent = "";

  if (!apiKey || !sharedSecret) {
    if (!apiKey) {
      document.getElementById("apiKeyError").textContent =
        "Please enter your API Key.";
    }
    if (!sharedSecret) {
      document.getElementById("secretError").textContent =
        "Please enter your Shared Secret.";
    }
    showError("Please fill in both fields.");
    return;
  }

  localStorage.setItem("lastfm_api_key", apiKey);
  localStorage.setItem("lastfm_shared_secret", sharedSecret);

  const callbackUrl = window.location.href.split("?")[0];
  window.location.href = `https://www.last.fm/api/auth/?api_key=${encodeURIComponent(
    apiKey
  )}&cb=${encodeURIComponent(callbackUrl)}`;
});

copyBtn.addEventListener("click", async () => {
  const sessionKey = sessionKeyOutput.textContent;
  try {
    await navigator.clipboard.writeText(sessionKey);
    copyBtn.textContent = "✓ Copied";
  } catch {
    copyBtn.textContent = "Copy failed";
  } finally {
    setTimeout(() => (copyBtn.textContent = "Copy to clipboard"), 1800);
  }
});

resetBtn.addEventListener("click", () => {
  apiKeyInput.value = "";
  sharedSecretInput.value = "";
  resultDiv.style.display = "none";
  errorDiv.style.display = "none";
  localStorage.removeItem("lastfm_api_key");
  localStorage.removeItem("lastfm_shared_secret");
});

toggleSecretBtn.addEventListener("click", () => {
  const isPassword = sharedSecretInput.type === "password";
  sharedSecretInput.type = isPassword ? "text" : "password";
  toggleSecretBtn.setAttribute(
    "aria-label",
    isPassword ? "Hide secret" : "Show secret"
  );
});

// ——— Core ———
async function getSessionKey(apiKey, sharedSecret, token) {
  setLoading(true);
  errorDiv.style.display = "none";
  resultDiv.style.display = "none";

  try {
    const params = {
      api_key: apiKey,
      method: "auth.getSession",
      token: token,
    };

    const sigString =
      Object.keys(params)
        .sort()
        .map((key) => key + params[key])
        .join("") + sharedSecret;

    const apiSig = md5(sigString);

    const url = new URL("https://ws.audioscrobbler.com/2.0/");
    url.searchParams.append("method", "auth.getSession");
    url.searchParams.append("api_key", apiKey);
    url.searchParams.append("token", token);
    url.searchParams.append("api_sig", apiSig);
    url.searchParams.append("format", "json");

    const response = await fetch(url.toString());
    const data = await response.json();

    setLoading(false);

    if (data.error) {
      showError(`Last.fm API error: ${data.message}`);
      return;
    }

    if (data.session && data.session.key) {
      showSuccess(data.session.key);
      // Clear stored credentials
      localStorage.removeItem("lastfm_api_key");
      localStorage.removeItem("lastfm_shared_secret");
    } else {
      showError("Unexpected response from Last.fm API.");
    }
  } catch (error) {
    setLoading(false);
    showError(`Error: ${error.message}`);
  }
}
