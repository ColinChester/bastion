// Passkey (WebAuthn) helpers for the Bastion console. No dependencies.
// The server sends options with base64url strings; the browser API wants ArrayBuffers.
(function () {
  "use strict";

  function fromB64u(text) {
    const pad = "=".repeat((4 - (text.length % 4)) % 4);
    const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  }

  function toB64u(buffer) {
    let bin = "";
    new Uint8Array(buffer).forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function post(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) { throw new Error(data.detail || data.error || "Request failed"); }
    return data;
  }

  function show(el, text, bad) {
    const out = el.closest("[data-item]").querySelector("[data-status]");
    out.textContent = text;
    out.className = bad ? "malicious" : "muted";
  }

  async function assertion(options) {
    options.challenge = fromB64u(options.challenge);
    (options.allowCredentials || []).forEach((c) => { c.id = fromB64u(c.id); });
    const cred = await navigator.credentials.get({ publicKey: options });
    return {
      id: cred.id, rawId: toB64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: toB64u(cred.response.clientDataJSON),
        authenticatorData: toB64u(cred.response.authenticatorData),
        signature: toB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? toB64u(cred.response.userHandle) : null,
      },
    };
  }

  // Safari (iPhone especially) only shows the passkey sheet when the request starts
  // directly from a tap. Fetching options first and then calling WebAuthn loses that
  // tap, and Safari refuses with NotAllowedError. So every passkey step takes two taps:
  // the first fetches the options, the second calls WebAuthn straight away.
  function explain(err) {
    if (err && err.name === "NotAllowedError") {
      return "Cancelled, or the browser blocked the passkey prompt. Tap the button again.";
    }
    if (err && err.name === "InvalidStateError") {
      return "This device already has a Bastion passkey.";
    }
    if (err && err.name === "SecurityError") {
      return "This address can't use Bastion's passkeys. Open the console at its tailnet https:// address.";
    }
    return String((err && err.message) || err);
  }

  const READY = "Continue with Face ID / Touch ID";

  // Buttons: data-passkey="approve|undo" data-id="…"; data-plain="deny|request-delete".
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-passkey], button[data-plain]");
    if (!btn) { return; }
    if (btn.dataset.plain) {
      btn.disabled = true;
      try {
        show(btn, "Working…");
        await post(`/api/${btn.dataset.plain}/${btn.dataset.id}`);
        location.reload();
      } catch (err) {
        show(btn, explain(err), true);
        btn.disabled = false;
      }
      return;
    }
    const kind = btn.dataset.passkey;
    if (!btn._start) {                       // tap 1: get the challenge
      btn.disabled = true;
      try {
        show(btn, "Getting ready…");
        btn._start = await post(`/api/${kind}/${btn.dataset.id}/options`);
        btn._label = btn._label || btn.textContent;
        btn.textContent = READY;
        show(btn, "Tap again to confirm.");
      } catch (err) {
        show(btn, explain(err), true);
      }
      btn.disabled = false;
      return;
    }
    const start = btn._start;                // tap 2: WebAuthn first, nothing before it
    btn._start = null;
    btn.disabled = true;
    try {
      const credential = await assertion(start.options);
      show(btn, "Checking…");
      const done = await post(`/api/${kind}/${btn.dataset.id}/verify`,
        { challenge_id: start.challenge_id, credential });
      if (!["executed", "undone"].includes(done.status)) {
        throw new Error(done.detail || done.status);
      }
      location.reload();
    } catch (err) {
      show(btn, explain(err), true);
      btn.textContent = btn._label;
      btn.disabled = false;
    }
  });

  const form = document.getElementById("enroll-form");
  if (form) {
    const out = document.getElementById("enroll-status");
    const button = form.querySelector("button[type=submit]");
    const label = button.textContent;
    let start = null;
    let startedCode = "";
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const code = form.elements.code.value.trim();
      out.className = "muted";
      if (!start || code !== startedCode) {   // tap 1: check the code, get options
        button.disabled = true;
        try {
          out.textContent = "Checking the code…";
          start = await post("/api/enroll/options", { code });
          startedCode = code;
          button.textContent = READY;
          out.textContent = "Code accepted. Tap the button again to create the passkey.";
        } catch (err) {
          start = null;
          out.className = "malicious";
          out.textContent = explain(err);
        }
        button.disabled = false;
        return;
      }
      const s = start;                        // tap 2: WebAuthn first, nothing before it
      start = null;
      button.disabled = true;
      try {
        const o = s.options;
        o.challenge = fromB64u(o.challenge);
        o.user.id = fromB64u(o.user.id);
        (o.excludeCredentials || []).forEach((c) => { c.id = fromB64u(c.id); });
        const cred = await navigator.credentials.create({ publicKey: o });
        out.textContent = "Checking…";
        await post("/api/enroll/verify", {
          code, challenge_id: s.challenge_id, name: form.elements.name.value.trim(),
          credential: {
            id: cred.id, rawId: toB64u(cred.rawId), type: cred.type,
            response: {
              clientDataJSON: toB64u(cred.response.clientDataJSON),
              attestationObject: toB64u(cred.response.attestationObject),
            },
          },
        });
        button.textContent = label;
        out.textContent = "Passkey registered. You can now approve actions from this device.";
      } catch (err) {
        button.textContent = label;
        out.className = "malicious";
        out.textContent = explain(err);
      }
      button.disabled = false;
    });
  }
})();
