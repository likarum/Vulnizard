// Browser notifications: registers the service worker and lets the user
// enable or disable Web Push for this browser. Served from the same origin.
// Two places use it: the Settings page (#push-box) and, in the
// administration, the offer shown when a test through a browser destination
// found no registered browser (#push-test).
(async () => {
  const box = document.getElementById("push-box");
  const offer = document.getElementById("push-test");
  if (!box && !offer) return;

  const supported = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;

  const toBytes = (base64url) => {
    const padded = base64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (base64url.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  };
  const post = (path, body) =>
    fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  // Tells the server which push address reaches this browser for the account
  const register = (subscription) =>
    post("/push/subscribe", { endpoint: subscription.endpoint, label: navigator.userAgent.slice(0, 80) });

  // Asks the permission, subscribes this browser and registers it for the
  // account. Answers nothing when done, or the reason it could not be.
  const subscribe = async (registration) => {
    const permission = await Notification.requestPermission();
    if (permission !== "granted") {
      return "The browser refused the permission to show notifications.";
    }
    try {
      const { key } = await (await fetch("/push/key")).json();
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: toBytes(key),
      });
      const response = await register(subscription);
      if (!response.ok) {
        await subscription.unsubscribe();
        return "The server refused this browser's subscription.";
      }
    } catch (e) {
      return "Could not enable notifications on this browser: " + ((e && (e.message || e.name)) || "unknown error") + ".";
    }
    return null;
  };

  // Settings page: the state of this browser, and the buttons changing it
  const settings = async () => {
    const status = box.querySelector("[data-status]");
    const enable = box.querySelector("[data-enable]");
    const disable = box.querySelector("[data-disable]");

    if (!supported) {
      status.textContent = "This browser does not support notifications (HTTPS or localhost is required).";
      return;
    }
    let registration;
    try {
      registration = await navigator.serviceWorker.register("/sw.js");
    } catch (e) {
      status.textContent = "Notifications are unavailable here (HTTPS or localhost is required).";
      return;
    }

    const refresh = async () => {
      const subscription = await registration.pushManager.getSubscription();
      // The browser may be subscribed while the server no longer knows it
      // (database restored, account created again): tell it again each time.
      if (subscription) {
        try {
          await register(subscription);
        } catch (e) {
          // offline: the next visit tells it
        }
      }
      enable.hidden = Boolean(subscription);
      disable.hidden = !subscription;
      status.textContent = subscription
        ? "Notifications are enabled on this browser."
        : "Notifications are not enabled on this browser.";
    };

    enable.addEventListener("click", async () => {
      const failure = await subscribe(registration);
      if (failure) {
        status.textContent = failure;
        return;
      }
      await refresh();
    });

    disable.addEventListener("click", async () => {
      const subscription = await registration.pushManager.getSubscription();
      if (subscription) {
        await post("/push/unsubscribe", { endpoint: subscription.endpoint });
        await subscription.unsubscribe();
      }
      await refresh();
    });

    await refresh();
  };

  // Administration: one button enables notifications on this browser, then
  // sends the test that found nobody to reach. Until the button is shown the
  // page keeps its text pointing to the Settings page.
  const testOffer = async () => {
    const status = offer.querySelector("[data-status]");
    const fallback = offer.querySelector("[data-fallback]");
    const enable = offer.querySelector("[data-enable]");
    const form = offer.querySelector("form");
    const say = (text) => {
      status.textContent = text;
      status.hidden = false;
    };

    if (!supported) {
      say("This browser cannot receive notifications (HTTPS or localhost is required).");
      return;
    }
    let registration;
    try {
      registration = await navigator.serviceWorker.register("/sw.js");
    } catch (e) {
      say("Notifications are unavailable here (HTTPS or localhost is required).");
      return;
    }
    fallback.hidden = true;
    enable.hidden = false;

    enable.addEventListener("click", async () => {
      enable.disabled = true;
      const failure = await subscribe(registration);
      if (failure) {
        say(failure);
        fallback.hidden = false;
        enable.disabled = false;
        return;
      }
      say("Notifications are enabled on this browser. Sending the test…");
      form.submit();
    });
  };

  if (box) await settings();
  if (offer) await testOffer();
})();
