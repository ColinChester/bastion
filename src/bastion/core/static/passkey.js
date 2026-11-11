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

  // Buttons: data-passkey="approve|undo" data-id="…"; data-plain="deny|request-delete".
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-passkey], button[data-plain]");
    if (!btn) { return; }
    btn.disabled = true;
    try {
      if (btn.dataset.plain) {
        show(btn, "Working…");
        await post(`/api/${btn.dataset.plain}/${btn.dataset.id}`);
      } else {
        const kind = btn.dataset.passkey;
        show(btn, "Waiting for your passkey…");
        const start = await post(`/api/${kind}/${btn.dataset.id}/options`);
        const credential = await assertion(start.options);
        show(btn, "Checking…");
        const done = await post(`/api/${kind}/${btn.dataset.id}/verify`,
          { challenge_id: start.challenge_id, credential });
        if (!["executed", "undone"].includes(done.status)) {
          throw new Error(done.detail || done.status);
        }
      }
      location.reload();
    } catch (err) {
      show(btn, err.name === "NotAllowedError" ? "Cancelled." : String(err.message || err), true);
      btn.disabled = false;
    }
  });

  const form = document.getElementById("enroll-form");
  if (form) {
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const out = document.getElementById("enroll-status");
      const code = form.elements.code.value.trim();
      try {
        out.className = "muted";
        out.textContent = "Waiting for your passkey…";
        const start = await post("/api/enroll/options", { code });
        const o = start.options;
        o.challenge = fromB64u(o.challenge);
        o.user.id = fromB64u(o.user.id);
        (o.excludeCredentials || []).forEach((c) => { c.id = fromB64u(c.id); });
        const cred = await navigator.credentials.create({ publicKey: o });
        await post("/api/enroll/verify", {
          code, challenge_id: start.challenge_id, name: form.elements.name.value.trim(),
          credential: {
            id: cred.id, rawId: toB64u(cred.rawId), type: cred.type,
            response: {
              clientDataJSON: toB64u(cred.response.clientDataJSON),
              attestationObject: toB64u(cred.response.attestationObject),
            },
          },
        });
        out.textContent = "Passkey registered. You can now approve actions from this device.";
      } catch (err) {
        out.className = "malicious";
        out.textContent = err.name === "NotAllowedError" ? "Cancelled." : String(err.message || err);
      }
    });
  }
})();
