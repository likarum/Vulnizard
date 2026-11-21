// Service worker of Vulnizard: shows browser notifications.
// A push carries no content: it wakes this worker, which asks the server
// (with the user's session) for the messages to display.
self.addEventListener("push", (event) => {
  event.waitUntil(
    (async () => {
      let items = [];
      try {
        const response = await fetch("/push/inbox", { credentials: "include", cache: "no-store" });
        if (response.ok) items = await response.json();
      } catch (e) {
        // offline or signed out: fall through to the generic message
      }
      if (!Array.isArray(items) || items.length === 0) {
        items = [{ title: "Vulnizard", body: "New activity — sign in to see it.", url: "/" }];
      }
      for (const item of items) {
        await self.registration.showNotification(String(item.title), {
          body: String(item.body),
          data: { url: String(item.url) },
        });
      }
    })()
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || "/";
  // Only paths of this site are opened
  const url = target.startsWith("/") && !target.startsWith("//") ? target : "/";
  event.waitUntil(self.clients.openWindow(url));
});
