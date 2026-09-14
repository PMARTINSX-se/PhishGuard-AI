"""
PhishGuard AI — Flask Inference API
Endpoints:
    POST /api/scan      { url } -> verdict, risk_score, confidence, reasons, recommendation
    POST /api/report    { url, reportedAt } -> stores report
    GET  /api/reports   -> list of recent reports
    GET  /api/stats     -> aggregate stats
    GET  /healthz       -> liveness probe
"""
import os
import sqlite3
import time
from contextlib import contextmanager

import joblib
import numpy as np
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

import json
from feature_extractor import extract_features, to_vector, build_explanations, build_url_sections, classify_threat_type
from email_analyzer import classify_email
from live_analyzer import live_check
import phishtank_feed

# ---------- config ----------
MODEL_PATH = os.environ.get("MODEL_PATH", "models/phishing_rf.pkl")
DB_PATH = os.environ.get("DB_PATH", "data/phishguard.db")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# ---------- model load ----------
if not os.path.exists(MODEL_PATH):
    raise SystemExit(f"Model not found at {MODEL_PATH} — run `python train_model.py` first.")
_bundle = joblib.load(MODEL_PATH)
MODEL = _bundle["model"]
FEATURE_NAMES = _bundle["feature_names"]
print(f"[+] Loaded model {MODEL.__class__.__name__} with {len(FEATURE_NAMES)} features")

# ---------- db ----------
@contextmanager
def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                hostname TEXT,
                verdict TEXT,
                risk_score INTEGER,
                confidence REAL,
                ts INTEGER,
                detail_json TEXT
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                hostname TEXT,
                reporter TEXT,
                status TEXT DEFAULT 'pending',
                ts INTEGER
            );
            CREATE TABLE IF NOT EXISTS blacklist (domain TEXT PRIMARY KEY, added_ts INTEGER);
            CREATE TABLE IF NOT EXISTS whitelist (domain TEXT PRIMARY KEY, added_ts INTEGER);
            CREATE TABLE IF NOT EXISTS email_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT,
                from_addr TEXT,
                subject TEXT,
                verdict TEXT,
                risk_score INTEGER,
                ts INTEGER,
                detail_json TEXT
            );
        """)
        # Older DBs created before detail_json existed — add it if missing (SQLite has no
        # "ADD COLUMN IF NOT EXISTS", so probe pragma table_info instead).
        for table in ("scans", "email_scans"):
            cols = [r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]
            if "detail_json" not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN detail_json TEXT")
init_db()

# ---------- app ----------
app = Flask(__name__)
CORS(app, origins="*")  # allow extension calls

# Live PhishTank feed — background thread, refreshed every few hours. Never blocks startup or
# a request: a slow/unreachable PhishTank just means feed checks find nothing until it succeeds.
phishtank_feed.start_background_refresh()

def classify(url: str, deep: bool = False):
    feats = extract_features(url)
    vec = np.array([to_vector(feats)])
    proba = MODEL.predict_proba(vec)[0]
    phish_prob = float(proba[1])
    risk_score = int(round(phish_prob * 100))

    reasons = build_explanations(feats, url)
    url_sections = build_url_sections(feats, url)
    live = None

    # Deep checks (TLS/WHOIS/redirect/content) are slow — only run when explicitly requested
    # (manual rescan, webapp scanner, email links), never on automatic every-tab-visit scans.
    if deep:
        try:
            live = live_check(url)
            risk_score = min(100, risk_score + live["score_delta"])
            url_sections = url_sections + live["bullets"]
            for b in live["bullets"]:
                if b["level"] in ("critical", "warning"):
                    reasons.append(b["text"])
        except Exception as e:
            live = {"signals": {}, "bullets": [], "score_delta": 0, "error": str(e)}

    if risk_score >= 70:
        verdict, recommendation = "phishing", "Avoid"
        if risk_score >= 85:
            recommendation = "Report"
    elif risk_score >= 35:
        verdict, recommendation = "suspicious", "Caution"
    else:
        verdict, recommendation = "safe", "Proceed"

    threat_type = classify_threat_type(feats, url) if verdict != "safe" else "None"
    return {
        "url": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": round(max(proba), 3),
        "reasons": reasons,
        "recommendation": recommendation,
        "features": feats,
        "threat_type": threat_type,
        "sections": {"url": url_sections},
        "live": live,
    }


@app.route("/healthz")
def healthz():
    return {"status": "ok", "model": MODEL.__class__.__name__}


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    deep = bool(data.get("deep"))
    if not url:
        return jsonify({"error": "url required"}), 400

    # Whitelist / blacklist override
    from urllib.parse import urlparse
    host = urlparse(url if "://" in url else "http://"+url).hostname or ""

    with db() as c:
        if c.execute("SELECT 1 FROM whitelist WHERE domain=?", (host,)).fetchone():
            return jsonify({
                "url": url, "verdict": "safe", "risk_score": 0,
                "confidence": 1.0, "reasons": ["Domain is whitelisted."],
                "recommendation": "Proceed",
            })
        if c.execute("SELECT 1 FROM blacklist WHERE domain=?", (host,)).fetchone():
            result = {"url": url, "verdict": "phishing", "risk_score": 100,
                      "confidence": 1.0, "reasons": ["Domain is blacklisted."],
                      "recommendation": "Avoid", "threat_type": "Blacklisted",
                      "sections": {"url": [{"level": "critical", "text": "Domain is on your blacklist."}]}}
            c.execute("INSERT INTO scans (url,hostname,verdict,risk_score,confidence,ts,detail_json) VALUES (?,?,?,?,?,?,?)",
                      (url, host, result["verdict"], result["risk_score"], result["confidence"], int(time.time()), json.dumps(result)))
            return jsonify(result)

    # Live PhishTank feed — a match here is a human-verified, currently-online phishing report,
    # so it's treated as authoritative rather than run through the probabilistic model.
    pt_match = phishtank_feed.check(url)
    if pt_match:
        result = {
            "url": url, "verdict": "phishing", "risk_score": 100, "confidence": 1.0,
            "reasons": [f"Listed on PhishTank's live verified-phishing feed (matched by {pt_match['matched']}: {pt_match['value']})."],
            "recommendation": "Avoid", "threat_type": "Confirmed Phishing (PhishTank)",
            "sections": {"url": [{"level": "critical", "text": "Confirmed on PhishTank's live feed of verified, currently-active phishing sites."}]},
        }
        with db() as c:
            c.execute("INSERT INTO scans (url,hostname,verdict,risk_score,confidence,ts,detail_json) VALUES (?,?,?,?,?,?,?)",
                      (url, host, result["verdict"], result["risk_score"], result["confidence"], int(time.time()), json.dumps(result)))
        return jsonify(result)

    result = classify(url, deep=deep)
    with db() as c:
        c.execute("INSERT INTO scans (url,hostname,verdict,risk_score,confidence,ts,detail_json) VALUES (?,?,?,?,?,?,?)",
                  (url, host, result["verdict"], result["risk_score"], result["confidence"], int(time.time()), json.dumps(result)))
    return jsonify(result)


@app.post("/api/report")
def api_report():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    with db() as c:
        c.execute("INSERT INTO reports (url,hostname,reporter,ts) VALUES (?,?,?,?)",
                  (url, host, request.remote_addr or "anon", int(time.time())))
    return jsonify({"ok": True})


@app.get("/api/reports")
def api_reports():
    with db() as c:
        rows = c.execute("SELECT * FROM reports ORDER BY ts DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/phishtank/status")
def api_phishtank_status():
    return jsonify(phishtank_feed.status())


@app.get("/api/stats")
def api_stats():
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        phish = c.execute("SELECT COUNT(*) FROM scans WHERE verdict='phishing'").fetchone()[0]
        susp  = c.execute("SELECT COUNT(*) FROM scans WHERE verdict='suspicious'").fetchone()[0]
        emails = c.execute("SELECT COUNT(*) FROM email_scans").fetchone()[0]
        email_phish = c.execute("SELECT COUNT(*) FROM email_scans WHERE verdict='phishing'").fetchone()[0]
    return jsonify({
        "total_scans": total, "phishing": phish, "suspicious": susp,
        "total_emails": emails, "email_phishing": email_phish,
    })


def _rows_with_detail(rows):
    out = []
    for r in rows:
        d = dict(r)
        raw = d.pop("detail_json", None)
        if raw:
            try:
                d["detail"] = json.loads(raw)
            except (TypeError, ValueError):
                d["detail"] = None
        else:
            d["detail"] = None
        out.append(d)
    return out


@app.get("/api/scans/recent")
def api_scans_recent():
    limit = min(int(request.args.get("limit", 50)), 200)
    with db() as c:
        urls = c.execute("SELECT * FROM scans ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        emails = c.execute("SELECT * FROM email_scans ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return jsonify({
        "urls": _rows_with_detail(urls),
        "emails": _rows_with_detail(emails),
    })


# ---------- email scanning ----------
def classify_url(url: str, deep: bool = False):
    """Same scoring path as /api/scan, reusable for scoring links found inside emails."""
    return classify(url, deep=deep)


@app.post("/api/email/scan")
def api_email_scan():
    data = request.get_json(silent=True) or {}
    headers = data.get("headers") or {}
    links = data.get("links") or []
    subject = data.get("subject") or ""
    snippet = data.get("snippet") or ""
    message_id = data.get("message_id") or ""

    if not headers and not links and not subject:
        return jsonify({"error": "headers, subject, or links required"}), 400

    # Email link scanning isn't on a page-load-latency path, so links always get the full
    # deep check (TLS/WHOIS/redirect/content), not just the static URL-string model.
    result = classify_email(headers, links, subject, snippet, lambda u: classify_url(u, deep=True))
    from_addr = (headers.get("From") or headers.get("from") or "").strip()
    result["message_id"] = message_id
    result["from"] = from_addr
    result["subject"] = subject

    with db() as c:
        c.execute(
            "INSERT INTO email_scans (message_id,from_addr,subject,verdict,risk_score,ts,detail_json) VALUES (?,?,?,?,?,?,?)",
            (message_id, from_addr, subject, result["verdict"], result["risk_score"], int(time.time()), json.dumps(result)),
        )
    return jsonify(result)


# ---------- Gmail OAuth token proxy ----------
# Stateless: the extension holds its own refresh_token (in chrome.storage.local); this backend
# only ever forwards a code/refresh_token to Google using the client_secret, which must never
# ship inside extension code. Nothing is persisted here.
def _require_google_oauth_config():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({"error": "Backend is missing GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET env vars."}), 500
    return None


@app.post("/api/gmail/oauth/exchange")
def api_gmail_oauth_exchange():
    err = _require_google_oauth_config()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    redirect_uri = (data.get("redirect_uri") or "").strip()
    if not code or not redirect_uri:
        return jsonify({"error": "code and redirect_uri required"}), 400

    resp = requests.post(GOOGLE_TOKEN_URL, data={
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }, timeout=15)
    if not resp.ok:
        return jsonify({"error": "token exchange failed", "details": resp.text}), 400
    return jsonify(resp.json())


@app.post("/api/gmail/oauth/refresh")
def api_gmail_oauth_refresh():
    err = _require_google_oauth_config()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    refresh_token = (data.get("refresh_token") or "").strip()
    if not refresh_token:
        return jsonify({"error": "refresh_token required"}), 400

    resp = requests.post(GOOGLE_TOKEN_URL, data={
        "refresh_token": refresh_token,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }, timeout=15)
    if not resp.ok:
        return jsonify({"error": "token refresh failed", "details": resp.text}), 400
    return jsonify(resp.json())


# ---------- whitelist / blacklist CRUD ----------
def _list_crud(table):
    if request.method == "GET":
        with db() as c:
            rows = c.execute(f"SELECT domain, added_ts FROM {table} ORDER BY added_ts DESC").fetchall()
        return jsonify([dict(r) for r in rows])

    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    if request.method == "POST":
        with db() as c:
            c.execute(f"INSERT OR REPLACE INTO {table} (domain, added_ts) VALUES (?, ?)", (domain, int(time.time())))
        return jsonify({"ok": True, "domain": domain})

    if request.method == "DELETE":
        with db() as c:
            c.execute(f"DELETE FROM {table} WHERE domain=?", (domain,))
        return jsonify({"ok": True, "domain": domain})


@app.route("/api/whitelist", methods=["GET", "POST", "DELETE"])
def api_whitelist():
    return _list_crud("whitelist")


@app.route("/api/blacklist", methods=["GET", "POST", "DELETE"])
def api_blacklist():
    return _list_crud("blacklist")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
