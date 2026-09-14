# PhishGuard AI — Real-Time Phishing Detection System

> Final-Year Project — Chrome Extension + Flask ML Backend + Admin Dashboard

A complete AI-powered phishing detection system that automatically scans every website you visit, extracts URL/SSL/content features, classifies them via a trained Random Forest model, and warns users in real time.

## What's in this bundle

```
phishguard/
├── extension/         → Chrome MV3 extension (load unpacked)
│   ├── manifest.json
│   ├── background.js  → service worker, tab monitoring, badge
│   ├── content.js     → page-level feature extraction
│   ├── popup.html/css/js → toolbar dashboard
│   ├── options.html   → user settings (whitelist, blacklist, API URL)
│   └── icons/
├── backend/           → Python Flask API + ML model
│   ├── app.py         → REST endpoints
│   ├── feature_extractor.py → 20-feature URL analyzer
│   ├── train_model.py → Random Forest training script
│   ├── test_model.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── data/, models/
├── webapp/             → installable PWA companion dashboard (desktop + mobile)
│   ├── index.html/app.js/style.css
│   ├── manifest.webmanifest, service-worker.js
│   └── icons/
├── desktop/            → Electron tray app (wraps webapp/, adds a Windows/Mac/Linux tray icon)
│   ├── package.json, main.js
│   └── (builds installers via `npm run dist`)
└── docs/              → architecture, flowcharts, diagrams (see PDF)
```

## Quick Start

### 1. Backend (terminal #1)
```bash
cd backend
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
python train_model.py                                 # trains on seed data
python app.py                                         # http://localhost:5000
```

### 2. Chrome extension
1. Open `chrome://extensions`
2. Toggle **Developer mode** (top-right)
3. Click **Load unpacked** → select the `extension/` folder
4. Pin the PhishGuard icon to the toolbar
5. Visit any site — the badge turns green/yellow/red automatically
6. Click the icon for the verdict + risk score + threat reasons

Works in Chrome, Edge, Brave, Arc, Opera (any Chromium browser).

### 3. Admin dashboard (this React app)
The live preview shows the admin console. Paste any URL into the analyzer to see the feature breakdown.

### 4. PWA companion dashboard (desktop + mobile)
A separate installable web app (`webapp/`) that talks to the same Flask backend — scan history, stats,
and whitelist/blacklist management, usable on desktop or your phone. The extension is still the only
thing that scans in real time; this is a companion view into the same backend/database.

```bash
cd webapp
python -m http.server 8080     # any static file server works
```
Then open `http://localhost:8080` in a desktop browser and click **Install app**, or from a phone on the
same Wi-Fi, open `http://<your-computer-LAN-IP>:8080` and use "Add to Home Screen". On the dashboard's
**Backend connection** card, point it at a backend reachable from that device:
- Desktop testing: `http://localhost:5000` (default)
- Phone on the same network: `http://<your-computer-LAN-IP>:5000` (Flask already binds `0.0.0.0`)
- Real mobile use away from your LAN: deploy `backend/` somewhere public (see Dockerfile) and use that URL

### 5. Gmail phishing scanning (extension feature)
The extension reads your inbox's headers and links (via a real OAuth code flow + the Gmail API) to flag
spoofed senders and malicious links, with a desktop notification when something looks off. It uses its
own refresh token (not Chrome's built-in silent-auth trick), so it stays connected reliably across
Chrome, Edge, and Brave — no more "reconnect every time you open the popup."

**`extension/manifest.json` already has a fixed `"key"`** (matching private key saved at the project
root as `dev-key.pem` — kept outside `extension/` on purpose, since Chrome warns if a private key sits
inside a loaded extension folder; you don't need to reuse it, it just makes the extension's ID identical
on Chrome/Edge/Brave: `pplmelipbjfhappapcfedppfaoancbhb`). That means the OAuth redirect URI below never
changes even if you reload the extension or switch browsers.

One-time Google Cloud setup — I can't create these credentials for you:

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → create/select a project.
2. **APIs & Services → Library** → enable **Gmail API**.
3. **APIs & Services → OAuth consent screen** → configure it (External is fine for personal testing),
   add the scope `https://www.googleapis.com/auth/gmail.readonly`, and add your Google account as a
   **test user** (this is the step that was missing before — without it you'll hit "Access blocked ...
   Error 403: access_denied").
4. **APIs & Services → Credentials → Create Credentials → OAuth client ID** → type **Web application**
   (not "Chrome Extension" — that type can't issue refresh tokens, which is what was causing the
   constant reconnects).
   - **Authorized redirect URI**: `https://pplmelipbjfhappapcfedppfaoancbhb.chromiumapp.org/`
5. Copy the generated **Client ID** and **Client secret**:
   - Client ID → paste into `extension/background.js` → `GMAIL_CLIENT_ID` constant, replacing
     `YOUR_WEB_CLIENT_ID.apps.googleusercontent.com`.
   - Client ID **and** Client secret → set as environment variables before starting the backend:
     ```bash
     export GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com     # Windows: set GOOGLE_CLIENT_ID=...
     export GOOGLE_CLIENT_SECRET=xxxx
     python app.py
     ```
     The client secret only ever lives on the backend — it never ships inside the extension.
6. Reload the extension, open the popup → **Mail** tab → **Connect Gmail**, approve the consent screen.

Once connected, `background.js` polls Gmail every few minutes (configurable in Settings), scores each new
message's headers + links via `POST /api/email/scan` on the backend, refreshes its access token itself
via `POST /api/gmail/oauth/refresh` (through the backend, using your client secret) whenever it's close to
expiring, and shows a notification plus a badge in the popup's Mail tab for anything `suspicious` or
`phishing`. Test-app refresh tokens from Google still expire after 7 days of inactivity — if that
happens, just Connect Gmail again.

### 6. Desktop tray app (Windows / macOS / Linux)
A small Electron wrapper (`desktop/`) that loads the same `webapp/` dashboard in a native window and adds
a real OS system tray icon — something no browser extension can do. Minimizing/closing the window keeps
it running in the tray; the tray menu has **Open Dashboard**, **Scan clipboard URL** (scans whatever URL
is on your clipboard and pops a native notification with the verdict), **Launch at login**, and **Quit**.

```bash
cd desktop
npm install
npm start              # runs the app with the backend expected at http://localhost:5000
```
To point it at a different backend, set `PHISHGUARD_API_BASE` before running (e.g.
`PHISHGUARD_API_BASE=http://192.168.1.20:5000 npm start`).

To build a real installer:
```bash
npm run dist            # electron-builder — output lands in desktop/dist/
```
electron-builder can only produce installers for the OS it's running on for some targets (e.g. a `.dmg`
requires building on macOS) — run `npm run dist` on each target OS rather than expecting one machine to
produce Windows/Mac/Linux installers all at once.

## Tech stack

| Layer | Technology |
|---|---|
| Extension | Manifest V3, vanilla HTML/CSS/JS, chrome.* APIs |
| Backend | Python 3.11, Flask, scikit-learn (Random Forest) |
| Model | 20 hand-crafted features, RF with 200 trees |
| Storage | SQLite (zero-setup) — swap to PostgreSQL for prod |
| Dashboard | React 18 + Vite + Tailwind |

## Documentation

See `PhishGuard-AI-Documentation.pdf` for the full final-year project report including:
- System architecture & flowcharts
- Feature extraction logic (20 features)
- Model training methodology + dataset sources
- Database schema (ER diagram)
- Testing strategy & evaluation metrics
- Deployment guide (local, Docker, cloud)

## Datasets

**`models/phishing_rf.pkl`** (the trained model) is built from `backend/data/urls.csv`, itself
assembled from three sources — run `python train_model.py --dataset data/urls.csv` to reproduce:
1. [Kaggle Phishing Site URLs](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) —
   the base set (`backend/data/phishing_site_urls.csv`, ~549K URLs, `good`/`bad`).
2. **Cisco Umbrella Popularity List** (a Tranco-equivalent top-1M legitimate domains list;
   Tranco itself wasn't reachable when this was built) — a sampled 150K root-domain safe examples,
   plus ~120K synthetically-generated realistic deep-link safe URLs (`/wiki/...`, `/watch?v=...`,
   `/in/username`, etc. across the top 20K Umbrella domains). Both exist to fix a real bug: the raw
   Kaggle set had **zero** bare-homepage safe examples and a short-path bias, which made the model
   misclassify ordinary URLs like `google.com` or `en.wikipedia.org/wiki/...` as phishing.
3. **PhishTank's live feed** (~76K currently-verified-online phishing URLs at time of training) —
   also layered in as a *separate, always-current* live blocklist check at scan time
   (`backend/phishtank_feed.py`), independent of the trained model; see below.

Compatible alternatives if you want to retrain further: [UCI Phishing Websites](https://archive.ics.uci.edu/dataset/327/phishing+websites)
(static, no live feed) or [Tranco](https://tranco-list.eu/) once/if it's reachable for you.

### Live PhishTank feed (not part of training — checked on every scan)
`backend/phishtank_feed.py` downloads [PhishTank's live feed](https://phishtank.org/developer_info.php)
(no API key needed) on a background thread, refreshed every 6 hours, cached to
`backend/data/phishtank_cache.json` so a restart isn't defenseless before the first refresh
completes. `/api/scan` checks this feed **before** the ML model — an exact URL or domain match is
treated as authoritative (verdict `phishing`, 100/100) since it's a human-verified report, not a
probabilistic guess. Check feed health any time via `GET /api/phishtank/status`.

## License
MIT — free to use for academic and commercial projects.
