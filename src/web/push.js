// Browser notifications: registers the service worker and lets the user
// enable or disable Web Push for this browser. Served from the same origin;
// the only script of the application besides the service worker.
(async () => {
  const box = document.getElementById("push-box");
  if (!box) return;
  const status = box.querySelector("[data-status]");
  const enable = box.querySelector("[data-enable]");
  const disable = box.querySelector("[data-disable]");

  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    status.textContent = "This browser does not support notifications (HTTPS or localhost is required).";
    return;
  }

  const toBytes = (base64url) => {
    const padded = base64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (base64url.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  };
  const post = (path, body) =>
    fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  let registration;
  try {
    registration = await navigator.serviceWorker.register("/sw.js");
  } catch (e) {
    status.textContent = "Notifications are unavailable here (HTTPS or localhost is required).";
    return;
  }

  const refresh = async () => {
    const subscription = await registration.pushManager.getSubscription();
    enable.hidden = Boolean(subscription);
    disable.hidden = !subscription;
    status.textContent = subscription
      ? "Notifications are enabled on this browser."
      : "Notifications are not enabled on this browser.";
  };

  enable.addEventListener("click", async () => {
    const permission = await Notification.requestPermission();
    if (permission !== "granted") {
      status.textContent = "The browser refused the permission to show notifications.";
      return;
    }
    try {
      const { key } = await (await fetch("/push/key")).json();
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: toBytes(key),
      });
      const response = await post("/push/subscribe", {
        endpoint: subscription.endpoint,
        label: navigator.userAgent.slice(0, 80),
      });
      if (!response.ok) {
        await subscription.unsubscribe();
        status.textContent = "The server refused this browser's subscription.";
        return;
      }
    } catch (e) {
      status.textContent =
        "Could not enable notifications on this browser: " + ((e && (e.message || e.name)) || "unknown error") + ".";
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
})();
