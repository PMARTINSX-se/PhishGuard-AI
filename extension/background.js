// PhishGuard AI — MV3 Background Service Worker
// Monitors active tabs, sends URLs to the local Flask ML backend, caches verdicts,
// updates the toolbar badge, fires notifications on confirmed phishing.

const API_BASE = "http://localhost:5000";  // change to your deployed backend URL
const CACHE_TTL_MS = 10 * 60 * 1000;       // 10 min
const cache = new Map();                    // url -> { result, ts }

// ---------- helpers ----------
async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return settings || {
    enabled: true,
    notifications: true,
    apiBase: API_BASE,
    whitelist: [],
    blacklist: [],
    gmailScanEnabled: true,
    gmailPollMinutes: 5,
  };
}

async function saveScanHistory(entry) {
  const { history = [] } = await chrome.storage.local.get("history");
  history.unshift(entry);
  await chrome.storage.local.set({ history: history.slice(0, 200) });
}

function setBadge(tabId, verdict) {
  const map = {
    safe:       { text: "✓",   color: "#16a34a" },
    suspicious: { text: "!",   color: "#f59e0b" },
    phishing:   { text: "✕",   color: "#dc2626" },
    error:      { text: "?",   color: "#64748b" },
  };
  const b = map[verdict] || map.error;
  chrome.action.setBadgeText({ text: b.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: b.color, tabId });
}

async function notifyPhishing(url, riskScore) {
  const settings = await getSettings();
  if (!settings.notifications) return;
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: "⚠ Phishing site detected",
    message: `${new URL(url).hostname} — risk ${riskScore}/100. PhishGuard recommends leaving immediately.`,
    priority: 2,
  });
}

// ---------- page-content signals (from content.js) ----------
// content.js runs on every page at document_idle and sends these for free — no network round
// trip needed, unlike live_analyzer.py's fetch-based content check on the backend. Used to
// sharpen the already-cached automatic scan result for this tab, not to trigger a new scan.
function pageFeatureBump(features) {
  let delta = 0;
  const reasons = [];
  if (features.hasPasswordField && features.externalFormSubmissions > 0) {
    delta += 30;
    reasons.push("Page has a password field whose form submits to a different domain — classic credential-harvesting pattern.");
  } else if (features.hasPasswordField) {
    delta += 8;
    reasons.push("Page contains a password input field.");
  }
  if (features.externalFormSubmissions > 0 && !features.hasPasswordField) {
    delta += 10;
    reasons.push(`${features.externalFormSubmissions} form(s) on this page submit to a different domain.`);
  }
  if (features.iframeCount >= 3) {
    delta += 5;
    reasons.push(`Page embeds ${features.iframeCount} iframes — sometimes used to hide malicious content.`);
  }
  return { delta: Math.min(40, delta), reasons };
}

async function handlePageFeatures(features, tabId) {
  if (!features?.url) return;
  const cached = cache.get(features.url);
  if (!cached) return; // scan hasn't landed in cache yet — nothing to sharpen

  const { delta, reasons } = pageFeatureBump(features);
  if (delta === 0) return;

  const result = { ...cached.result };
  result.risk_score = Math.min(100, (result.risk_score || 0) + delta);
  result.reasons = [...(result.reasons || []), ...reasons];
  if (result.risk_score >= 70) result.verdict = "phishing";
  else if (result.risk_score >= 35 && result.verdict === "safe") result.verdict = "suspicious";

  cache.set(features.url, { result, ts: cached.ts });
  if (tabId != null) setBadge(tabId, result.verdict);
  if (result.verdict === "phishing" && cached.result.verdict !== "phishing") {
    notifyPhishing(features.url, result.risk_score);
  }
}

// ---------- core scan ----------
// deep=true requests the backend's live network checks (TLS/WHOIS/redirect/content) — slow
// (a few seconds), so it's only ever passed from manual/important triggers (popup Rescan
// button, webapp scanner), never from the automatic per-tab-visit scans below, which always
// call this with deep left false so browsing never feels slowed down.
async function scanUrl(url, tabId, deep = false) {
  if (!url || !/^https?:/.test(url)) return null;

  const settings = await getSettings();
  if (!settings.enabled) {
    setBadge(tabId, "safe");
    return null;
  }

  const host = new URL(url).hostname;
  if (settings.whitelist.includes(host)) {
    const r = { verdict: "safe", risk_score: 0, reasons: ["Whitelisted by user"], recommendation: "Proceed" };
    setBadge(tabId, "safe");
    return r;
  }
  if (settings.blacklist.includes(host)) {
    const r = { verdict: "phishing", risk_score: 100, reasons: ["Blacklisted by user"], recommendation: "Avoid" };
    setBadge(tabId, "phishing");
    notifyPhishing(url, 100);
    return r;
  }

  // Cache — a deep scan always hits the network fresh (the cached entry may only be a fast
  // static-only result), but its result still gets written back to the cache afterward so
  // subsequent fast lookups on this tab benefit from the sharper verdict too.
  if (!deep) {
    const cached = cache.get(url);
    if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
      setBadge(tabId, cached.result.verdict);
      return cached.result;
    }
  }

  try {
    const resp = await fetch(`${settings.apiBase}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, deep }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const result = await resp.json();
    cache.set(url, { result, ts: Date.now() });
    setBadge(tabId, result.verdict);
    saveScanHistory({ url, host, ...result, ts: Date.now() });
    if (result.verdict === "phishing") notifyPhishing(url, result.risk_score);
    return result;
  } catch (e) {
    console.warn("[PhishGuard] backend unreachable, using local heuristic", e);
    const result = localHeuristic(url);
    cache.set(url, { result, ts: Date.now() });
    setBadge(tabId, result.verdict);
    return result;
  }
}

// ---------- offline fallback heuristic ----------
function localHeuristic(url) {
  const u = new URL(url);
  let score = 0;
  const reasons = [];
  if (u.protocol !== "https:") { score += 18; reasons.push("No HTTPS"); }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) { score += 22; reasons.push("Raw IP host"); }
  if ([".tk",".ml",".ga",".cf",".gq",".xyz"].some(t => u.hostname.endsWith(t))) { score += 14; reasons.push("Suspicious TLD"); }
  if (u.hostname.split(".").length > 4) { score += 12; reasons.push("Deep subdomain"); }
  const kw = ["verify","secure","login","update","confirm","wallet","suspended"];
  const hits = kw.filter(k => url.toLowerCase().includes(k));
  if (hits.length) { score += Math.min(20, hits.length*7); reasons.push("Suspicious keywords: "+hits.join(",")); }
  if (url.length > 75) { score += 8; reasons.push("Long URL"); }

  let verdict = "safe", recommendation = "Proceed";
  if (score >= 60) { verdict = "phishing"; recommendation = "Avoid"; }
  else if (score >= 25) { verdict = "suspicious"; recommendation = "Caution"; }
  if (!reasons.length) reasons.push("No phishing indicators detected (offline mode)");

  return { verdict, risk_score: Math.min(100, score), confidence: 0.6, reasons, recommendation, offline: true };
}

// ---------- Gmail scanning ----------
// Uses a real OAuth authorization-code flow (via chrome.identity.launchWebAuthFlow) rather than
// chrome.identity.getAuthToken — the latter's silent token refresh only works reliably in Google
// Chrome (it leans on Chrome's built-in Google-account integration) and fails non-interactively
// on Edge/Brave, forcing a reconnect far too often. This flow gets a refresh_token we manage
// ourselves, so it behaves the same on every Chromium browser.
const GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me";

// Public OAuth client ID (not secret — safe to ship in extension code). Create this as a
// "Web application" OAuth client in Google Cloud Console; see README for exact steps.
const GMAIL_CLIENT_ID = "863168750615-02oljc45jdtc7ltc5g6qou4qplu33h8a.apps.googleusercontent.com";
const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const TOKEN_REFRESH_SKEW_MS = 60 * 1000; // refresh 60s before actual expiry

async function connectGmail() {
  const settings = await getSettings();
  const redirectUri = chrome.identity.getRedirectURL();
  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.search = new URLSearchParams({
    client_id: GMAIL_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: GMAIL_SCOPE,
    access_type: "offline",
    prompt: "consent",
  }).toString();

  const resultUrl = await new Promise((resolve) => {
    chrome.identity.launchWebAuthFlow({ url: authUrl.toString(), interactive: true }, (redirect) => {
      if (chrome.runtime.lastError || !redirect) {
        console.warn("[PhishGuard] Gmail auth flow failed:", chrome.runtime.lastError?.message);
        resolve(null);
      } else {
        resolve(redirect);
      }
    });
  });
  if (!resultUrl) return false;

  const code = new URL(resultUrl).searchParams.get("code");
  if (!code) return false;

  try {
    const resp = await fetch(`${settings.apiBase}/api/gmail/oauth/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, redirect_uri: redirectUri }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const tokens = await resp.json();
    await chrome.storage.local.set({
      gmailAuth: {
        refresh_token: tokens.refresh_token,
        access_token: tokens.access_token,
        expires_at: Date.now() + (tokens.expires_in || 3600) * 1000,
      },
    });
    return true;
  } catch (e) {
    console.warn("[PhishGuard] Gmail token exchange failed", e);
    return false;
  }
}

async function getValidAccessToken() {
  const { gmailAuth } = await chrome.storage.local.get("gmailAuth");
  if (!gmailAuth) return null;

  if (gmailAuth.access_token && gmailAuth.expires_at - TOKEN_REFRESH_SKEW_MS > Date.now()) {
    return gmailAuth.access_token;
  }
  if (!gmailAuth.refresh_token) return null;

  const settings = await getSettings();
  try {
    const resp = await fetch(`${settings.apiBase}/api/gmail/oauth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: gmailAuth.refresh_token }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const tokens = await resp.json();
    const updated = {
      ...gmailAuth,
      access_token: tokens.access_token,
      expires_at: Date.now() + (tokens.expires_in || 3600) * 1000,
    };
    await chrome.storage.local.set({ gmailAuth: updated });
    return updated.access_token;
  } catch (e) {
    console.warn("[PhishGuard] Gmail token refresh failed", e);
    return null;
  }
}

async function disconnectGmail() {
  const { gmailAuth } = await chrome.storage.local.get("gmailAuth");
  if (gmailAuth?.access_token) {
    fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(gmailAuth.access_token)}`, {
      method: "POST",
    }).catch(() => {});
  }
  await chrome.storage.local.remove(["gmailAuth", "gmailSeenIds", "gmailScans"]);
}

function b64urlDecode(data) {
  try {
    const norm = data.replace(/-/g, "+").replace(/_/g, "/");
    return decodeURIComponent(escape(atob(norm)));
  } catch {
    return "";
  }
}

function extractLinksFromHtml(html) {
  const links = new Set();
  const hrefRe = /href=["']([^"']+)["']/gi;
  let m;
  while ((m = hrefRe.exec(html))) {
    if (/^https?:\/\//i.test(m[1])) links.add(m[1]);
  }
  const bareRe = /https?:\/\/[^\s"'<>)]+/gi;
  let b;
  while ((b = bareRe.exec(html))) links.add(b[0]);
  return Array.from(links).slice(0, 25);
}

function findParts(payload, out = []) {
  if (!payload) return out;
  if (payload.body?.data) out.push({ mimeType: payload.mimeType, data: payload.body.data });
  (payload.parts || []).forEach((p) => findParts(p, out));
  return out;
}

function parseGmailMessage(msg) {
  const headers = {};
  (msg.payload?.headers || []).forEach((h) => { headers[h.name] = h.value; });

  const parts = findParts(msg.payload);
  let html = "", text = "";
  parts.forEach((p) => {
    const decoded = b64urlDecode(p.data);
    if (p.mimeType === "text/html") html += decoded;
    else if (p.mimeType === "text/plain") text += decoded;
  });
  const links = extractLinksFromHtml(html || text);

  return {
    message_id: msg.id,
    headers,
    subject: headers["Subject"] || "",
    snippet: msg.snippet || "",
    links,
  };
}

async function analyzeEmail(parsed) {
  const settings = await getSettings();
  try {
    const resp = await fetch(`${settings.apiBase}/api/email/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch (e) {
    console.warn("[PhishGuard] backend unreachable for email scan, using local heuristic", e);
    return localEmailHeuristic(parsed);
  }
}

function localEmailHeuristic(parsed) {
  let score = 0;
  const reasons = [];
  const from = (parsed.headers["From"] || "").toLowerCase();
  const replyTo = (parsed.headers["Reply-To"] || "").toLowerCase();
  if (replyTo && from && !from.includes(replyTo.split("@")[1] || " ")) {
    score += 20; reasons.push("Reply-To differs from From domain");
  }
  const urgentKw = ["verify your account", "act now", "suspended", "click here", "urgent"];
  const body = `${parsed.subject} ${parsed.snippet}`.toLowerCase();
  const hits = urgentKw.filter((k) => body.includes(k));
  if (hits.length) { score += hits.length * 10; reasons.push("Urgency language detected"); }
  if ((parsed.links || []).length) reasons.push(`${parsed.links.length} link(s) found (unscored offline)`);

  let verdict = "safe", recommendation = "Proceed";
  if (score >= 40) { verdict = "phishing"; recommendation = "Avoid"; }
  else if (score >= 20) { verdict = "suspicious"; recommendation = "Caution"; }
  if (!reasons.length) reasons.push("No phishing indicators detected (offline mode)");

  return {
    verdict, risk_score: Math.min(100, score), reasons, recommendation,
    links: [], offline: true, message_id: parsed.message_id,
    from: parsed.headers["From"] || "", subject: parsed.subject,
  };
}

async function notifyPhishingEmail(result) {
  const settings = await getSettings();
  if (!settings.notifications) return;
  chrome.notifications.create(`pg-mail-${result.message_id}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: "⚠ Suspicious email detected",
    message: `${result.from || "Unknown sender"} — "${result.subject || "(no subject)"}" — risk ${result.risk_score}/100.`,
    priority: 2,
  });
}

async function saveEmailScan(result) {
  const { gmailScans = [] } = await chrome.storage.local.get("gmailScans");
  gmailScans.unshift({ ...result, ts: Date.now() });
  await chrome.storage.local.set({ gmailScans: gmailScans.slice(0, 100) });
}

async function pollGmail() {
  const settings = await getSettings();
  if (!settings.gmailScanEnabled) return;

  const token = await getValidAccessToken();
  if (!token) return; // not connected yet — user must click "Connect Gmail" in the popup

  try {
    const listResp = await fetch(
      `${GMAIL_API}/messages?q=${encodeURIComponent("newer_than:1d in:inbox")}&maxResults=15`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!listResp.ok) throw new Error(`Gmail list HTTP ${listResp.status}`);
    const { messages = [] } = await listResp.json();

    const { gmailSeenIds = [] } = await chrome.storage.local.get("gmailSeenIds");
    const seen = new Set(gmailSeenIds);
    const fresh = messages.filter((m) => !seen.has(m.id));

    for (const m of fresh) {
      const msgResp = await fetch(`${GMAIL_API}/messages/${m.id}?format=full`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!msgResp.ok) continue;
      const full = await msgResp.json();
      const parsed = parseGmailMessage(full);
      const result = await analyzeEmail(parsed);
      await saveEmailScan(result);
      if (result.verdict === "phishing" || result.verdict === "suspicious") {
        await notifyPhishingEmail(result);
      }
      seen.add(m.id);
    }

    await chrome.storage.local.set({ gmailSeenIds: Array.from(seen).slice(-500) });
  } catch (e) {
    console.warn("[PhishGuard] Gmail poll failed", e);
  }
}

// ---------- listeners ----------
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status === "complete" && tab.url) {
    await scanUrl(tab.url, tabId);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  // The tab can close (or navigate away) between the activation event firing and this async
  // lookup running — chrome.tabs.get then rejects with "No tab with id: N", which otherwise
  // surfaces as an uncaught promise rejection in the extension's Errors log. Harmless, just noise.
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url) await scanUrl(tab.url, tabId);
  } catch (e) {
    console.debug("[PhishGuard] tab no longer available for scan:", e.message);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "PAGE_FEATURES") {
    handlePageFeatures(msg.features, sender.tab?.id);
    return false; // no response needed
  }
  if (msg.type === "RESCAN") {
    scanUrl(msg.url, msg.tabId, !!msg.deep).then(sendResponse);
    return true;  // async
  }
  if (msg.type === "REPORT") {
    fetch(`${API_BASE}/api/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(msg.payload),
    }).then(r => r.json()).then(sendResponse).catch(() => sendResponse({ ok: false }));
    return true;
  }
  if (msg.type === "GMAIL_CONNECT") {
    connectGmail().then(async (ok) => {
      if (ok) await pollGmail();
      sendResponse({ ok });
    });
    return true;
  }
  if (msg.type === "GMAIL_DISCONNECT") {
    disconnectGmail().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "GMAIL_POLL_NOW") {
    pollGmail().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "GMAIL_STATUS") {
    getValidAccessToken().then((token) => sendResponse({ connected: !!token }));
    return true;
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "pg-gmail-poll") pollGmail();
});

async function scheduleGmailAlarm() {
  const settings = await getSettings();
  chrome.alarms.create("pg-gmail-poll", { periodInMinutes: settings.gmailPollMinutes || 5 });
}

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get("settings");
  if (!existing.settings) {
    await chrome.storage.local.set({
      settings: {
        enabled: true, notifications: true, apiBase: API_BASE, whitelist: [], blacklist: [],
        gmailScanEnabled: true, gmailPollMinutes: 5,
      },
    });
  }
  await scheduleGmailAlarm();
  console.log("[PhishGuard] installed");
});

chrome.runtime.onStartup?.addListener(scheduleGmailAlarm);
