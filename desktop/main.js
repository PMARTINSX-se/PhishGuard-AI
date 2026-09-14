// PhishGuard AI Electron desktop tray app.
// Wraps the existing webapp/ dashboard (same HTML/CSS/JS as the installable PWA) in a native
// window, adds a system tray icon with quick actions, and minimizes-to-tray instead of quitting
// on window close. Works on Windows, macOS, and Linux from this one codebase.
const { app, BrowserWindow, Tray, Menu, clipboard, Notification, nativeImage, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs");
const http = require("http");
const https = require("https");
const { URL } = require("url");

const WEBAPP_DIR = path.join(__dirname, "..", "webapp");
const ICON_PATH = path.join(WEBAPP_DIR, "icons", "icon-512.png");

let mainWindow = null;
let tray = null;
app.isQuitting = false;

function getApiBase() {
  // Mirrors the webapp's own localStorage default; the desktop app has no shared storage with
  // the browser's localStorage, so this uses the same DEFAULT_API fallback as webapp/app.js.
  return process.env.PHISHGUARD_API_BASE || "http://localhost:5000";
}

function postJson(urlStr, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const lib = url.protocol === "https:" ? https : http;
    const data = JSON.stringify(body);
    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
      },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(raw));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 760,
    icon: ICON_PATH,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, "preload.js"),
    },
  });
  mainWindow.loadFile(path.join(WEBAPP_DIR, "index.html"));

  // Minimize to tray instead of quitting when the user clicks the window's close button.
  mainWindow.on("close", (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

async function scanClipboardUrl() {
  const text = clipboard.readText().trim();
  if (!/^https?:\/\//i.test(text)) {
    new Notification({ title: "PhishGuard AI", body: "Clipboard doesn't contain a URL to scan." }).show();
    return;
  }
  try {
    const result = await postJson(`${getApiBase()}/api/scan`, { url: text });
    new Notification({
      title: `PhishGuard: ${(result.verdict || "unknown").toUpperCase()}`,
      body: `${text}\nRisk ${result.risk_score ?? "?"}/100 — ${result.recommendation || ""}`,
    }).show();
  } catch (e) {
    new Notification({ title: "PhishGuard AI", body: `Backend unreachable at ${getApiBase()}` }).show();
  }
}

function createTray() {
  const icon = nativeImage.createFromPath(ICON_PATH).resize({ width: 16, height: 16 });
  tray = new Tray(icon);
  tray.setToolTip("PhishGuard AI");

  const menu = Menu.buildFromTemplate([
    { label: "Open Dashboard", click: () => { mainWindow.show(); mainWindow.focus(); } },
    { label: "Scan clipboard URL", click: scanClipboardUrl },
    { type: "separator" },
    {
      label: "Launch at login",
      type: "checkbox",
      checked: app.getLoginItemSettings().openAtLogin,
      click: (item) => app.setLoginItemSettings({ openAtLogin: item.checked }),
    },
    { type: "separator" },
    { label: "Quit PhishGuard AI", click: () => { app.isQuitting = true; app.quit(); } },
  ]);
  tray.setContextMenu(menu);
  tray.on("click", () => { mainWindow.show(); mainWindow.focus(); });
}

// Renders the current page to a real PDF file and lets the user pick where to save it — a true
// download, instead of the webapp's browser fallback (window.print(), which opens the OS print
// dialog). Chromium's PDF renderer respects the page's existing @media print stylesheet, so this
// picks up the same print-only investigation-report layout without any extra work.
ipcMain.handle("export-investigation-pdf", async (_event, suggestedName) => {
  if (!mainWindow) return { ok: false, error: "no window" };
  try {
    const pdfBuffer = await mainWindow.webContents.printToPDF({ printBackground: true, pageSize: "A4" });
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: "Save Investigation Report",
      defaultPath: suggestedName || "PhishGuard-Investigation-Report.pdf",
      filters: [{ name: "PDF", extensions: ["pdf"] }],
    });
    if (canceled || !filePath) return { ok: false, canceled: true };
    await fs.promises.writeFile(filePath, pdfBuffer);
    return { ok: true, filePath };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

app.whenReady().then(() => {
  createWindow();
  createTray();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
    else mainWindow.show();
  });
});

// Keep running in the tray on all platforms when every window is closed (that's the point of a
// tray app). Electron's default is to quit here unless this listener exists and doesn't call
// app.quit() itself in practice this only fires if a window is destroyed outright, since the
// window's own "close" handler above already intercepts the normal close-button path.
app.on("window-all-closed", () => {});
