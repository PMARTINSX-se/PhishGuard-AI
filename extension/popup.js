// Popup UI shows verdict for the active tab.
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function render(result, host) {
  const card = document.getElementById("verdict-card");
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
        <div class="score ${v === 'safe' ? '' : ''}" style="color: var(--${v === 'safe' ? 'success' : v === 'suspicious' ? 'warning' : 'danger'})">
          ${result.risk_score}<span class="score-out">/100</span>
        </div>
      </div>
    </div>
    <div class="bar"><div class="bar-fill ${v}" style="width:${result.risk_score}%"></div></div>
  `;

  document.getElementById("host").textContent = host;
  document.getElementById("confidence").textContent = ((result.confidence ?? 0.7) * 100).toFixed(0) + "%";

  const reasons = document.getElementById("reasons");
  reasons.innerHTML = "";
  (result.reasons || ["No details"]).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    reasons.appendChild(li);
  });

  const recSection = document.getElementById("rec-section");
  const recText = document.getElementById("rec-text");
  recText.className = "rec-text " + (result.recommendation || "Proceed");
  recText.textContent = result.recommendation || "Proceed";
  recSection.hidden = false;

  document.getElementById("status-dot").className = "dot " + (result.offline ? "dot-off" : "dot-on");
  document.getElementById("status-dot").title = result.offline ? "Backend offline — using local heuristic" : "Backend online";
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

// ---------- Mail tab ----------
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

function setupTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  buttons.forEach((btn) => {
    btn.onclick = () => {
      buttons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-site").hidden = btn.dataset.tab !== "site";
      document.getElementById("tab-mail").hidden = btn.dataset.tab !== "mail";
      if (btn.dataset.tab === "mail") refreshMailTab();
    };
  });
}

document.addEventListener("DOMContentLoaded", () => {
  scan();
  setupTabs();
  setupMailTab();
  document.getElementById("rescan-btn").onclick = () => scan(true);

  document.getElementById("report-btn").onclick = async () => {
    const tab = await getActiveTab();
    chrome.runtime.sendMessage({ type: "REPORT", payload: { url: tab.url, reportedAt: Date.now() } });
    document.getElementById("report-btn").textContent = "✓ Reported";
  };

  document.getElementById("whitelist-btn").onclick = async () => {
    const tab = await getActiveTab();
    const host = new URL(tab.url).hostname;
    const { settings } = await chrome.storage.local.get("settings");
    settings.whitelist = Array.from(new Set([...(settings.whitelist || []), host]));
    await chrome.storage.local.set({ settings });
    document.getElementById("whitelist-btn").textContent = "✓ Added";
    setTimeout(scan, 300);
  };

  document.getElementById("open-options").onclick = (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  };
});
