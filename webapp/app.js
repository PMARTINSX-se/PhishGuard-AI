// PhishGuard PWA dashboard talks directly to the Flask backend (CORS is open on the backend).
const DEFAULT_API = "http://localhost:5000";

function getApiBase() {
  return localStorage.getItem("pg_api_base") || DEFAULT_API;
}
function setApiBase(v) {
  localStorage.setItem("pg_api_base", v);
}

async function api(path, opts) {
  const base = getApiBase().replace(/\/$/, "");
  const resp = await fetch(base + path, opts);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

// ---------- URL scan ----------
async function runScan() {
  const input = document.getElementById("scan-input");
  const url = input.value.trim();
  if (!url) return;
  const btn = document.getElementById("scan-btn");
  btn.disabled = true; btn.textContent = "Scanning…";
  try {
    // Manual scan from the dashboard; always request the full deep check (TLS/WHOIS/redirect/
    // content), unlike the extension's automatic per-tab scans which stay fast/static-only.
    const result = await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, deep: true }),
    });
    renderScanResult(result);
    loadHistory();
    loadStats();
  } catch (e) {
    renderScanResult({ verdict: "error", risk_score: 0, reasons: [`Backend unreachable at ${getApiBase()}; ${e.message}`] });
  } finally {
    btn.disabled = false; btn.textContent = "Scan";
  }
}

let lastScanResult = null;

function renderScanResult(result) {
  lastScanResult = result;
  const box = document.getElementById("scan-result");
  box.classList.add("show");
  const badge = document.getElementById("result-badge");
  badge.textContent = result.verdict;
  badge.className = "verdict-badge " + result.verdict;
  document.getElementById("result-score").textContent = result.risk_score != null ? `Risk ${result.risk_score}/100` : "";
  const ul = document.getElementById("result-reasons");
  ul.innerHTML = "";
  (result.reasons || []).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    ul.appendChild(li);
  });
  const investigateBtn = document.getElementById("result-investigate-btn");
  investigateBtn.hidden = !result.sections;
}

// ---------- Investigation report ----------
function fillBullets(sectionId, listId, bullets) {
  const section = document.getElementById(sectionId);
  const list = document.getElementById(listId);
  if (!bullets || !bullets.length) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  list.innerHTML = "";
  bullets.forEach((b) => {
    const li = document.createElement("li");
    li.className = b.level || "warning";
    li.textContent = b.text;
    list.appendChild(li);
  });
}

function openInvestigation(result) {
  if (!result) return;
  const sections = result.sections || {};
  document.getElementById("inv-target").textContent = result.subject
    ? `${result.subject}${result.from ? "; " + result.from : ""}`
    : result.url || "";

  const verdictEl = document.getElementById("inv-verdict");
  const verdictLabel = { safe: "🟢 LOW RISK", suspicious: "🟡 MODERATE RISK", phishing: "🔴 HIGH RISK" }[result.verdict] || result.verdict;
  verdictEl.textContent = verdictLabel;
  verdictEl.className = "inv-verdict " + result.verdict;
  document.getElementById("inv-risk-score").textContent = result.risk_score ?? "—";

  fillBullets("inv-sender-section", "inv-sender-bullets", sections.sender);
  fillBullets("inv-url-section", "inv-url-bullets", sections.url);
  fillBullets("inv-content-section", "inv-content-bullets", sections.content);

  document.getElementById("inv-threat-type").textContent = result.threat_type || "Unknown";
  document.getElementById("inv-recommendation").textContent = result.recommendation || "—";

  document.getElementById("inv-overlay").hidden = false;
}

function closeInvestigation() {
  document.getElementById("inv-overlay").hidden = true;
}

async function exportInvestigationReport() {
  const btn = document.getElementById("inv-export-btn");
  const target = document.getElementById("inv-target").textContent.trim();
  const safeName = (target || "report").replace(/[\\/:*?"<>|]+/g, "-").slice(0, 60);
  const suggestedName = `PhishGuard-Investigation-${safeName}.pdf`;

  // Inside the Electron tray app, preload.js exposes a real native Save dialog + file write:
  // an actual download. In a plain browser/PWA context there's no such API, so fall back to
  // window.print(), which still produces a clean PDF via the browser's own "Save as PDF"
  // destination (the page's @media print rules apply either way).
  if (window.phishguard?.isElectron) {
    const original = btn.textContent;
    btn.disabled = true; btn.textContent = "Saving…";
    try {
      const result = await window.phishguard.exportInvestigationPDF(suggestedName);
      if (result.ok) {
        btn.textContent = "✓ Saved";
      } else if (!result.canceled) {
        btn.textContent = original;
        alert(`Couldn't save PDF: ${result.error || "unknown error"}`);
      } else {
        btn.textContent = original;
      }
    } finally {
      btn.disabled = false;
      setTimeout(() => { btn.textContent = original; }, 2000);
    }
    return;
  }

  window.print();
}

// ---------- stats ----------
async function loadStats() {
  try {
    const s = await api("/api/stats");
    document.getElementById("stat-total").textContent = s.total_scans ?? "—";
    document.getElementById("stat-phish").textContent = s.phishing ?? "—";
    document.getElementById("stat-susp").textContent = s.suspicious ?? "—";
    document.getElementById("stat-emails").textContent = s.total_emails ?? "—";
  } catch {
    ["stat-total", "stat-phish", "stat-susp", "stat-emails"].forEach((id) => (document.getElementById(id).textContent = "—"));
  }
}

// ---------- history ----------
let historyRecords = []; // flat list of {detail} so row clicks can reopen the investigation report

async function loadHistory() {
  const body = document.getElementById("history-body");
  try {
    const { urls = [], emails = [] } = await api("/api/scans/recent?limit=25");
    historyRecords = [];
    const rows = [
      ...urls.map((r) => ({ label: r.url, kind: "url", ...r })),
      ...emails.map((r) => ({ label: `✉ ${r.subject || "(no subject)"}`, kind: "email", ...r })),
    ].sort((a, b) => b.ts - a.ts);

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="4" class="muted">No scans yet.</td></tr>';
      return;
    }
    body.innerHTML = rows
      .map((r, i) => {
        historyRecords[i] = r.detail || null;
        return `<tr class="clickable" data-idx="${i}">
          <td class="url" title="${escapeHtml(r.label)}">${escapeHtml(r.label)}</td>
          <td><span class="tag ${r.verdict}">${r.verdict}</span></td>
          <td>${r.risk_score}</td>
          <td class="muted">${new Date(r.ts * 1000).toLocaleString()}</td>
        </tr>`;
      })
      .join("");
    body.querySelectorAll("tr[data-idx]").forEach((tr) => {
      tr.onclick = () => {
        const detail = historyRecords[Number(tr.dataset.idx)];
        if (detail) openInvestigation(detail);
      };
    });
  } catch {
    body.innerHTML = `<tr><td colspan="4" class="muted">Backend unreachable at ${escapeHtml(getApiBase())}.</td></tr>`;
  }
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- whitelist / blacklist ----------
async function refreshLists() {
  for (const kind of ["whitelist", "blacklist"]) {
    const rowsEl = document.getElementById(`${kind}-rows`);
    try {
      const rows = await api(`/api/${kind}`);
      rowsEl.innerHTML = rows.length
        ? rows.map((r) => `
            <div class="domain-row">
              <span>${escapeHtml(r.domain)}</span>
              <button class="ghost" data-kind="${kind}" data-domain="${escapeHtml(r.domain)}">Remove</button>
            </div>`).join("")
        : '<p class="muted" style="font-size:11px;padding:6px 0">None yet.</p>';
    } catch {
      rowsEl.innerHTML = '<p class="muted" style="font-size:11px">Backend unreachable.</p>';
    }
  }
  document.querySelectorAll("[data-kind][data-domain]").forEach((btn) => {
    btn.onclick = async () => {
      await api(`/api/${btn.dataset.kind}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: btn.dataset.domain }),
      });
      refreshLists();
    };
  });
}

async function addToList(kind, inputId) {
  const input = document.getElementById(inputId);
  const domain = input.value.trim().toLowerCase();
  if (!domain) return;
  await api(`/api/${kind}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  input.value = "";
  refreshLists();
}

// ---------- PWA install prompt ----------
let deferredInstallPrompt = null;
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  document.getElementById("install-btn").hidden = false;
});

// ---------- init ----------
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("api-base-input").value = getApiBase();
  document.getElementById("scan-btn").onclick = runScan;
  document.getElementById("scan-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runScan();
  });
  document.getElementById("api-base-save").onclick = () => {
    setApiBase(document.getElementById("api-base-input").value.trim().replace(/\/$/, ""));
    loadStats(); loadHistory(); refreshLists();
  };
  document.getElementById("whitelist-add").onclick = () => addToList("whitelist", "whitelist-input");
  document.getElementById("blacklist-add").onclick = () => addToList("blacklist", "blacklist-input");
  document.getElementById("result-investigate-btn").onclick = () => openInvestigation(lastScanResult);
  document.getElementById("inv-close").onclick = closeInvestigation;
  document.getElementById("inv-overlay").addEventListener("click", (e) => {
    if (e.target.id === "inv-overlay") closeInvestigation();
  });
  document.getElementById("inv-export-btn").onclick = () => exportInvestigationReport();
  document.getElementById("install-btn").onclick = async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    document.getElementById("install-btn").hidden = true;
  };

  loadStats();
  loadHistory();
  refreshLists();

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("service-worker.js").catch(() => {});
  }
});
