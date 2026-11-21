// Passkeys (WebAuthn): registration from the settings and second step of the login.
(function () {
  "use strict";

  function decode(text) {
    var padded = text.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var raw = atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }

  function encode(buffer) {
    var bytes = new Uint8Array(buffer);
    var raw = "";
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function post(url, body) {
    var response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    var data = {};
    try { data = await response.json(); } catch (e) { /* no body */ }
    if (!response.ok) throw new Error(data.error || "The request failed.");
    return data;
  }

  function show(box, message) {
    var target = box.querySelector("[data-passkey-message]");
    if (target) target.textContent = message;
  }

  async function register(box) {
    var password = box.querySelector("[name=password]").value;
    var name = box.querySelector("[name=name]").value;
    var options = await post("/settings/mfa/passkeys/start", { password: password, name: name });
    var key = options.publicKey;
    key.challenge = decode(key.challenge);
    key.user.id = decode(key.user.id);
    (key.excludeCredentials || []).forEach(function (c) { c.id = decode(c.id); });
    var credential = await navigator.credentials.create({ publicKey: key });
    var done = await post("/settings/mfa/passkeys/finish", {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      extensions: {},
      response: {
        attestationObject: encode(credential.response.attestationObject),
        clientDataJSON: encode(credential.response.clientDataJSON),
      },
    });
    window.location.assign(done.redirect || "/settings/mfa");
  }

  function assertionOf(assertion) {
    return {
      id: assertion.id,
      rawId: encode(assertion.rawId),
      type: assertion.type,
      extensions: {},
      response: {
        authenticatorData: encode(assertion.response.authenticatorData),
        clientDataJSON: encode(assertion.response.clientDataJSON),
        signature: encode(assertion.response.signature),
        userHandle: assertion.response.userHandle ? encode(assertion.response.userHandle) : null,
      },
    };
  }

  // Sign-in with the passkey alone: the authenticator tells which account it is
  async function signin() {
    var options = await post("/login/passkey/start", {});
    var key = options.publicKey;
    key.challenge = decode(key.challenge);
    (key.allowCredentials || []).forEach(function (c) { c.id = decode(c.id); });
    var assertion = await navigator.credentials.get({ publicKey: key });
    var done = await post("/login/passkey/finish", assertionOf(assertion));
    window.location.assign(done.redirect || "/");
  }

  async function login() {
    var options = await post("/login/mfa/passkey/start", {});
    var key = options.publicKey;
    key.challenge = decode(key.challenge);
    (key.allowCredentials || []).forEach(function (c) { c.id = decode(c.id); });
    var assertion = await navigator.credentials.get({ publicKey: key });
    var done = await post("/login/mfa/passkey/finish", assertionOf(assertion));
    window.location.assign(done.redirect || "/");
  }

  function bind(selector, action) {
    var box = document.querySelector(selector);
    if (!box) return;
    var button = box.querySelector("button[data-passkey]");
    if (!window.PublicKeyCredential) {
      show(box, "This browser does not support passkeys.");
      if (button) button.disabled = true;
      return;
    }
    box.addEventListener("submit", function (event) { event.preventDefault(); });
    button.addEventListener("click", function () {
      button.disabled = true;
      show(box, "Waiting for the passkey…");
      action(box).catch(function (error) {
        show(box, error && error.name === "NotAllowedError" ? "Cancelled or timed out." : (error.message || "It did not work."));
        button.disabled = false;
      });
    });
  }

  bind("#passkey-register", register);
  bind("#passkey-login", login);
  bind("#passkey-signin", signin);
})();
