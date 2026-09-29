// Popup UI shows verdict for the active tab.
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return settings || {
    enabled: true, notifications: true, apiBase: "http://localhost:5000",
    whitelist: [], blacklist: [], gmailScanEnabled: true, gmailPollMinutes: 5,
    deepScanEnabled: true,
  };
}

// ids: the element-id suffixes to render into; lets the same renderer drive both the Home
// tab's per-tab verdict card and the Scan tab's manual-URL result, which are separate DOM trees.
function render(result, host, ids = {
  card: "verdict-card", host: "host", confidence: "confidence", reasons: "reasons",
  recSection: "rec-section", recText: "rec-text",
}) {
  const card = document.getElementById(ids.card);
  const v = result.verdict;
  card.classList.remove("safe", "suspicious", "phishing");
  card.classList.add(v);

  const label = { safe: "Safe", suspicious: "Suspicious", phishing: "Phishing" }[v];
  card.innerHTML = `
    <div class="verdict-row">
      <div>
        <div class="verdict-label">Verdict</div>
        <div class="verdict-text ${v}">${label}</div>
      </div>
      <div style="text-align:right">
        <div class="verdict-label">Risk</div>
        <div class="score" style="color: var(--${v === 'safe' ? 'success' : v === 'suspicious' ? 'warning' : 'danger'})">
          ${result.risk_score}<span class="score-out">/100</span>
        </div>
      </div>
    </div>
    <div class="bar"><div class="bar-fill ${v}" style="width:${result.risk_score}%"></div></div>
  `;

  document.getElementById(ids.host).textContent = host;
  document.getElementById(ids.confidence).textContent = ((result.confidence ?? 0.7) * 100).toFixed(0) + "%";

  const reasons = document.getElementById(ids.reasons);
  reasons.innerHTML = "";
  (result.reasons || ["No details"]).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    reasons.appendChild(li);
  });

  const recSection = document.getElementById(ids.recSection);
  const recText = document.getElementById(ids.recText);
  recText.className = "rec-text " + (result.recommendation || "Proceed");
  recText.textContent = result.recommendation || "Proceed";
  recSection.hidden = false;

  document.getElementById("status-dot").className = "dot " + (result.offline ? "dot-off" : "dot-on");
  document.getElementById("status-dot").title = result.offline ? "Backend offline; using local heuristic" : "Backend online";
}

async function scan(deep = false) {
  const tab = await getActiveTab();
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    document.getElementById("verdict-card").innerHTML = '<div class="verdict-loading"><span>This page cannot be scanned.</span></div>';
    return;
  }
  if (deep) {
    const card = document.getElementById("verdict-card");
    card.innerHTML = '<div class="verdict-loading"><div class="spinner"></div><span>Deep-scanning (TLS, domain age, page content)...</span></div>';
  }
  const result = await chrome.runtime.sendMessage({ type: "RESCAN", url: tab.url, tabId: tab.id, deep });
  if (result) render(result, new URL(tab.url).hostname);
}

// ---------- Scan tab: manual, not tied to any open tab ----------
const SCAN_IDS = {
  card: "scan-verdict-card", host: "scan-host", confidence: "scan-confidence",
  reasons: "scan-reasons", recSection: "scan-rec-section", recText: "scan-rec-text",
};

function normalizeUrl(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

async function runManualScan() {
  const input = document.getElementById("scan-url-input");
  const url = normalizeUrl(input.value);
  if (!url) return;
  try {
    new URL(url);
  } catch {
    return;
  }

  const btn = document.getElementById("scan-url-btn");
  const wrap = document.getElementById("scan-result-wrap");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  wrap.hidden = false;
  document.getElementById(SCAN_IDS.card).className = "verdict-card";
  document.getElementById(SCAN_IDS.card).innerHTML = '<div class="verdict-loading"><div class="spinner"></div><span>Scanning...</span></div>';

  const settings = await getSettings();
  // No tabId; this URL isn't necessarily open anywhere, so there's no toolbar badge to update
  // (background.js's setBadge guards against a null tabId for exactly this case).
  const result = await chrome.runtime.sendMessage({ type: "RESCAN", url, tabId: undefined, deep: settings.deepScanEnabled });
  btn.disabled = false;
  btn.textContent = "Scan";
  if (result) render(result, new URL(url).hostname, SCAN_IDS);
}

function setupScanTab() {
  document.getElementById("scan-url-btn").onclick = runManualScan;
  document.getElementById("scan-url-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runManualScan();
  });
}

// ---------- Mail/Email tab ----------
function renderMailList(scans) {
  const list = document.getElementById("mail-list");
  if (!scans.length) {
    list.innerHTML = '<li class="muted">No emails scanned yet.</li>';
    return;
  }
  list.innerHTML = "";
  scans.slice(0, 25).forEach((s) => {
    const li = document.createElement("li");
    li.className = "mail-item";
    li.innerHTML = `
      <span class="mail-badge ${s.verdict}">${s.verdict}</span>
      <span class="mail-subject">${(s.subject || "(no subject)").replace(/</g, "&lt;")}</span>
      <span class="mail-from">${(s.from || "").replace(/</g, "&lt;")}</span>
    `;
    li.onclick = () => {
      if (s.message_id) {
        chrome.tabs.create({ url: `https://mail.google.com/mail/u/0/#inbox/${s.message_id}` });
      }
    };
    list.appendChild(li);
  });
}

async function refreshMailTab() {
  const { connected } = await chrome.runtime.sendMessage({ type: "GMAIL_STATUS" });
  document.getElementById("mail-connect").hidden = connected;
  document.getElementById("mail-panel").hidden = !connected;
  if (connected) {
    const { gmailScans = [] } = await chrome.storage.local.get("gmailScans");
    renderMailList(gmailScans);
  }
}

function setupMailTab() {
  document.getElementById("gmail-connect-btn").onclick = async (e) => {
    e.target.textContent = "Connecting…";
    const { ok } = await chrome.runtime.sendMessage({ type: "GMAIL_CONNECT" });
    e.target.textContent = "Connect Gmail";
    if (ok) refreshMailTab();
    else alert("Gmail connection failed or was cancelled. Check that OAuth is configured in manifest.json.");
  };
  document.getElementById("gmail-disconnect-btn").onclick = async () => {
    await chrome.runtime.sendMessage({ type: "GMAIL_DISCONNECT" });
    refreshMailTab();
  };
  document.getElementById("gmail-poll-btn").onclick = async (e) => {
    e.target.textContent = "Checking…";
    await chrome.runtime.sendMessage({ type: "GMAIL_POLL_NOW" });
    e.target.textContent = "↻ Check now";
    refreshMailTab();
  };
}

// ---------- Settings tab (account + condensed options) ----------
async function refreshAccountInfo() {
  const { account } = await chrome.runtime.sendMessage({ type: "PG_ACCOUNT_STATUS" });
  document.getElementById("account-email").textContent = account?.email || "—";
  return account;
}

async function loadSettingsForm() {
  const settings = await getSettings();
  document.getElementById("set-enabled").checked = settings.enabled ?? true;
  document.getElementById("set-notifications").checked = settings.notifications ?? true;
  document.getElementById("set-apibase").value = settings.apiBase || "http://localhost:5000";
  document.getElementById("set-whitelist").value = (settings.whitelist || []).join("\n");
  document.getElementById("set-blacklist").value = (settings.blacklist || []).join("\n");
  document.getElementById("set-gmail-enabled").checked = settings.gmailScanEnabled ?? true;
  document.getElementById("set-gmail-poll").value = settings.gmailPollMinutes || 5;
}

function setupSettingsTab() {
  document.getElementById("account-logout-btn").onclick = async () => {
    await chrome.runtime.sendMessage({ type: "PG_LOGOUT" });
    showGate(); // logging out drops straight back to the sign-in gate
  };

  document.getElementById("open-options").onclick = (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  };

  document.getElementById("settings-save-btn").onclick = async () => {
    const newSettings = {
      enabled: document.getElementById("set-enabled").checked,
      notifications: document.getElementById("set-notifications").checked,
      apiBase: document.getElementById("set-apibase").value.trim().replace(/\/$/, ""),
      whitelist: document.getElementById("set-whitelist").value.split("\n").map((s) => s.trim()).filter(Boolean),
      blacklist: document.getElementById("set-blacklist").value.split("\n").map((s) => s.trim()).filter(Boolean),
      gmailScanEnabled: document.getElementById("set-gmail-enabled").checked,
      gmailPollMinutes: Math.max(1, parseInt(document.getElementById("set-gmail-poll").value, 10) || 5),
      deepScanEnabled: (await getSettings()).deepScanEnabled ?? true, // owned by the Home protection tile, not this form
    };
    await chrome.storage.local.set({ settings: newSettings });
    chrome.alarms.create("pg-gmail-poll", { periodInMinutes: newSettings.gmailPollMinutes });
    refreshProtectionTiles();
    const m = document.getElementById("settings-msg");
    m.textContent = "✓ Saved";
    setTimeout(() => { m.textContent = ""; }, 2000);
  };
}

// ---------- Home: greeting + rotating quote ----------
const QUOTES = {
  morning: [
    "A clear inbox and a clear head; let's keep both that way.",
    "Every link you don't click is a scam that didn't work.",
    "Start the day the way you'll want to end it: unphished.",
  ],
  afternoon: [
    "Halfway through the day, still zero phish caught. Nice.",
    "A little suspicion goes a long way.",
    "Verify first, click second.",
  ],
  evening: [
    "Winding down? Scammers don't; stay sharp.",
    "One more scan before you log off never hurts.",
    "Trust, but verify the link.",
  ],
  night: [
    "Burning the midnight oil? PhishGuard's still watching.",
    "Late-night browsing, same vigilance.",
    "Even at this hour, don't trust a link that feels off.",
  ],
};

function getDaypart() {
  const h = new Date().getHours();
  if (h >= 5 && h < 12) return "morning";
  if (h >= 12 && h < 17) return "afternoon";
  if (h >= 17 && h < 22) return "evening";
  return "night";
}

function renderGreeting(firstName) {
  const daypart = getDaypart();
  const label = { morning: "Good morning", afternoon: "Good afternoon", evening: "Good evening", night: "Good night" }[daypart];
  const name = (firstName || "").trim();
  document.getElementById("greeting-text").textContent = name ? `${label}, ${name}` : label;

  const pool = QUOTES[daypart];
  document.getElementById("greeting-quote").textContent = pool[Math.floor(Math.random() * pool.length)];
}

// ---------- Protection tiles ----------
const TILE_KEYS = ["enabled", "gmailScanEnabled", "deepScanEnabled"];
const TILE_IDS = { enabled: "tile-web", gmailScanEnabled: "tile-email", deepScanEnabled: "tile-deep" };

async function refreshProtectionTiles() {
  const settings = await getSettings();
  TILE_KEYS.forEach((key) => {
    const id = TILE_IDS[key];
    const tile = document.getElementById(id);
    const on = !!settings[key];
    tile.classList.toggle("on", on);
    document.getElementById(`${id}-state`).textContent = on ? "On" : "Off";
  });
}

function setupProtectionTiles() {
  TILE_KEYS.forEach((key) => {
    const tile = document.getElementById(TILE_IDS[key]);
    tile.onclick = async () => {
      const settings = await getSettings();
      settings[key] = !settings[key];
      await chrome.storage.local.set({ settings });
      if (key === "gmailScanEnabled") {
        chrome.alarms.create("pg-gmail-poll", { periodInMinutes: settings.gmailPollMinutes || 5 });
      }
      refreshProtectionTiles();
    };
  });
}

// ---------- Bottom nav ----------
function setupNav() {
  const buttons = document.querySelectorAll(".nav-btn");
  buttons.forEach((btn) => {
    btn.onclick = () => {
      buttons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-home").hidden = btn.dataset.tab !== "home";
      document.getElementById("tab-scan").hidden = btn.dataset.tab !== "scan";
      document.getElementById("tab-email").hidden = btn.dataset.tab !== "email";
      document.getElementById("tab-settings").hidden = btn.dataset.tab !== "settings";
      if (btn.dataset.tab === "email") refreshMailTab();
      if (btn.dataset.tab === "settings") { refreshAccountInfo(); loadSettingsForm(); }
    };
  });
}

// ---------- Auth gate ----------
// This is the first thing shown on every popup open. The rest of the app only appears once a
// PhishGuard account is signed in.
function showGate(error) {
  document.getElementById("auth-gate").hidden = false;
  document.getElementById("app-shell").hidden = true;
  const banner = document.getElementById("gate-error");
  if (error) {
    banner.textContent = error;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

async function showApp() {
  document.getElementById("auth-gate").hidden = true;
  document.getElementById("app-shell").hidden = false;
  scan();
  refreshProtectionTiles();
  const account = await refreshAccountInfo();
  renderGreeting(account?.firstName);
}

async function attemptConnect(button, mode) {
  const original = button.textContent;
  button.textContent = "Opening login…";
  button.disabled = true;
  await chrome.runtime.sendMessage({ type: "PG_CONNECT", mode });
  button.textContent = original;
  button.disabled = false;

  // The login tab is open, not completed yet; poll briefly so the popup reacts to
  // success/failure on its own without the user needing to reopen it.
  let attempts = 0;
  const poll = setInterval(async () => {
    attempts += 1;
    const { account, error } = await chrome.runtime.sendMessage({ type: "PG_ACCOUNT_STATUS" });
    if (account) {
      clearInterval(poll);
      showApp();
    } else if (error) {
      clearInterval(poll);
      showGate(error);
    } else if (attempts >= 20) {
      clearInterval(poll); // ~30s timeout; leave the gate as-is, tab is presumably still open
    }
  }, 1500);
}

function setupGate() {
  document.getElementById("gate-connect-btn").onclick = (e) => attemptConnect(e.target, "login");
  document.getElementById("gate-signup-link").onclick = (e) => {
    e.preventDefault();
    attemptConnect(document.getElementById("gate-connect-btn"), "signup");
  };
}

function setupAppActions() {
  setupNav();
  setupScanTab();
  setupMailTab();
  setupSettingsTab();
  setupProtectionTiles();
  document.getElementById("rescan-btn").onclick = () => scan(true);

  document.getElementById("report-btn").onclick = async () => {
    const tab = await getActiveTab();
    chrome.runtime.sendMessage({ type: "REPORT", payload: { url: tab.url, reportedAt: Date.now() } });
    document.getElementById("report-btn").textContent = "✓ Reported";
  };

  document.getElementById("whitelist-btn").onclick = async () => {
    const tab = await getActiveTab();
    const host = new URL(tab.url).hostname;
    const settings = await getSettings();
    settings.whitelist = Array.from(new Set([...(settings.whitelist || []), host]));
    await chrome.storage.local.set({ settings });
    document.getElementById("whitelist-btn").textContent = "✓ Added";
    setTimeout(scan, 300);
  };
}

document.addEventListener("DOMContentLoaded", async () => {
  setupGate();
  setupAppActions();
  const { account, error } = await chrome.runtime.sendMessage({ type: "PG_ACCOUNT_STATUS" });
  if (account) showApp();
  else showGate(error);
});
