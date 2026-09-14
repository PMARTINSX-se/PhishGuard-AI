(async () => {
  const { settings = {} } = await chrome.storage.local.get("settings");
  document.getElementById("enabled").checked = settings.enabled ?? true;
  document.getElementById("notifications").checked = settings.notifications ?? true;
  document.getElementById("apiBase").value = settings.apiBase || "http://localhost:5000";
  document.getElementById("whitelist").value = (settings.whitelist || []).join("\n");
  document.getElementById("blacklist").value = (settings.blacklist || []).join("\n");
  document.getElementById("gmailScanEnabled").checked = settings.gmailScanEnabled ?? true;
  document.getElementById("gmailPollMinutes").value = settings.gmailPollMinutes || 5;
  document.getElementById("save").onclick = async () => {
    const newSettings = {
      enabled: document.getElementById("enabled").checked,
      notifications: document.getElementById("notifications").checked,
      apiBase: document.getElementById("apiBase").value.trim().replace(/\/$/, ""),
      whitelist: document.getElementById("whitelist").value.split("\n").map(s=>s.trim()).filter(Boolean),
      blacklist: document.getElementById("blacklist").value.split("\n").map(s=>s.trim()).filter(Boolean),
      gmailScanEnabled: document.getElementById("gmailScanEnabled").checked,
      gmailPollMinutes: Math.max(1, parseInt(document.getElementById("gmailPollMinutes").value, 10) || 5),
    };
    await chrome.storage.local.set({ settings: newSettings });
    chrome.alarms.create("pg-gmail-poll", { periodInMinutes: newSettings.gmailPollMinutes });
    const m = document.getElementById("msg"); m.textContent = "✓ Saved"; setTimeout(()=>m.textContent="", 2000);
  };
})();