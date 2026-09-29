"""
PhishGuard AI; Flask Inference API
Endpoints:
    POST /api/scan      { url } -> verdict, risk_score, confidence, reasons, recommendation
    POST /api/report    { url, reportedAt } -> stores report
    GET  /api/reports   -> list of recent reports
    GET  /api/stats     -> aggregate stats
    GET  /healthz       -> liveness probe
"""
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from contextlib import contextmanager
from email.mime.text import MIMEText

import joblib
import numpy as np
import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

import json
from feature_extractor import extract_features, to_vector, build_explanations, build_url_sections, classify_threat_type
from email_analyzer import classify_email
from live_analyzer import live_check
from known_safe_domains import is_known_safe_domain
import phishtank_feed

# ---------- config ----------
MODEL_PATH = os.environ.get("MODEL_PATH", "models/phishing_rf.pkl")
DB_PATH = os.environ.get("DB_PATH", "data/phishguard.db")
WEBAPP_DIR = os.environ.get("WEBAPP_DIR", os.path.join(os.path.dirname(__file__), "..", "webapp"))
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
# SMTP creds for account-verification emails. Not the same account as Gmail OAuth above; this is
# the mailbox PhishGuard itself sends FROM (e.g. a Gmail account with an app password).
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

# ---------- model load ----------
if not os.path.exists(MODEL_PATH):
    raise SystemExit(f"Model not found at {MODEL_PATH}; run `python train_model.py` first.")
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
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                account_type TEXT DEFAULT 'individual',
                first_name TEXT,
                last_name TEXT,
                job_title TEXT,
                company TEXT,
                birth_date TEXT,
                employee_count TEXT,
                email_verified INTEGER DEFAULT 0,
                created_ts INTEGER
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                created_ts INTEGER
            );
            CREATE TABLE IF NOT EXISTS email_verifications (
                email TEXT PRIMARY KEY,
                code TEXT NOT NULL,
                expires_ts INTEGER NOT NULL,
                sent_ts INTEGER NOT NULL,
                attempts INTEGER DEFAULT 0
            );
        """)
        # Older DBs created before detail_json existed; add it if missing (SQLite has no
        # "ADD COLUMN IF NOT EXISTS", so probe pragma table_info instead).
        for table in ("scans", "email_scans"):
            cols = [r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]
            if "detail_json" not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN detail_json TEXT")
        # Older DBs created before the Individual/Organization signup fields existed.
        user_cols = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        for col, decl in [
            ("account_type", "TEXT DEFAULT 'individual'"), ("first_name", "TEXT"), ("last_name", "TEXT"),
            ("job_title", "TEXT"), ("company", "TEXT"), ("birth_date", "TEXT"), ("employee_count", "TEXT"),
            ("email_verified", "INTEGER DEFAULT 0"),
        ]:
            if col not in user_cols:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")
                if col == "email_verified":
                    # Accounts created before verification existed already logged in fine under
                    # the old flow; don't retroactively lock them out.
                    c.execute("UPDATE users SET email_verified=1")
init_db()

# ---------- app ----------
app = Flask(__name__)
CORS(app, origins="*")  # allow extension calls

# Live PhishTank feed; background thread, refreshed every few hours. Never blocks startup or
# a request: a slow/unreachable PhishTank just means feed checks find nothing until it succeeds.
phishtank_feed.start_background_refresh()

def classify(url: str, deep: bool = False):
    feats = extract_features(url)

    # Known-major-domain short-circuit: the URL-string model was trained on a dataset where the
    # "safe" class skewed toward short, simple URLs, so long/parameter-heavy (but completely
    # ordinary) URLs on sites like Google Search, YouTube, or an OAuth flow scored as phishing.
    # For an unambiguous major domain, no ML score should ever be needed to establish safety.
    if is_known_safe_domain(url):
        return {
            "url": url, "verdict": "safe", "risk_score": 0, "confidence": 1.0,
            "reasons": ["Recognized major/trusted domain"], "recommendation": "Proceed",
            "features": feats, "threat_type": "None",
            "sections": {"url": [{"level": "ok", "text": "Domain is a recognized major, trusted organization."}]},
            "live": None,
        }

    vec = np.array([to_vector(feats)])
    proba = MODEL.predict_proba(vec)[0]
    phish_prob = float(proba[1])
    risk_score = int(round(phish_prob * 100))

    reasons = build_explanations(feats, url)
    url_sections = build_url_sections(feats, url)
    live = None

    # Deep checks (TLS/WHOIS/redirect/content) are slow; only run when explicitly requested
    # (manual rescan, webapp scanner, email links), never on automatic every-tab-visit scans.
    if deep:
        try:
            live = live_check(url)
            risk_score = max(0, min(100, risk_score + live["score_delta"]))
            url_sections = url_sections + live["bullets"]
            for b in live["bullets"]:
                if b["level"] in ("critical", "warning"):
                    reasons.append(b.get("short", b["text"]))
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

    # Live PhishTank feed; a match here is a human-verified, currently-online phishing report,
    # so it's treated as authoritative rather than run through the probabilistic model.
    pt_match = phishtank_feed.check(url)
    if pt_match:
        result = _phishtank_result(url, pt_match)
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
def _phishtank_result(url: str, pt_match: dict) -> dict:
    return {
        "url": url, "verdict": "phishing", "risk_score": 100, "confidence": 1.0,
        "reasons": ["Listed on PhishTank"],
        "recommendation": "Avoid", "threat_type": "Confirmed Phishing (PhishTank)",
        "sections": {"url": [{"level": "critical", "text": "Confirmed on PhishTank's live feed of verified, currently-active phishing sites."}]},
    }


def classify_url(url: str, deep: bool = False):
    """Scoring path for links found inside emails. Same as /api/scan, including the live
    PhishTank check; previously that check only ran on direct scans, so a link in an email
    that PhishTank had already confirmed as phishing was scored by the model alone."""
    pt_match = phishtank_feed.check(url)
    if pt_match:
        return _phishtank_result(url, pt_match)
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

    # One row per Gmail message: a re-scan replaces the earlier verdict instead of adding a
    # duplicate, so a stale (e.g. pre-fix false-positive) result doesn't linger in history/stats.
    with db() as c:
        if message_id:
            c.execute("DELETE FROM email_scans WHERE message_id=?", (message_id,))
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


# ---------- PhishGuard account (local-only) ----------
# A user account on THIS machine only; same SQLite DB as everything else in this project, not a
# hosted multi-device service. It exists purely to give the extension a "Connect with PhishGuard"
# login/signup flow (matching the UX pattern of hosted competitors) without taking on the real
# security/hosting stakes of an actual public-facing account system.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Server-side mirror of the "8+ chars, upper, lower, number, symbol" hint shown on the signup
# form; the hint is worthless if the backend doesn't actually enforce it.
PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$")
# Common public webmail domains; organisation signups need a business email, same as the
# reference product. Not exhaustive; good enough to block the obvious cases.
PUBLIC_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com",
    "aol.com", "protonmail.com", "proton.me", "mail.com", "yandex.com", "gmx.com",
}
EMPLOYEE_COUNT_RANGES = {"1-10", "11-50", "51-200", "201-500", "501-1000", "1000+"}


VERIFICATION_CODE_TTL = 10 * 60   # 10 minutes
VERIFICATION_RESEND_COOLDOWN = 30  # seconds
VERIFICATION_MAX_ATTEMPTS = 6


def _smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS)


def _send_verification_email(email: str, code: str):
    msg = MIMEText(
        f"Your PhishGuard AI verification code is: {code}\n\n"
        f"This code expires in 10 minutes. If you didn't request this, you can ignore this email."
    )
    msg["Subject"] = f"{code} is your PhishGuard AI verification code"
    msg["From"] = SMTP_FROM
    msg["To"] = email
    # Port 465 is implicit-TLS (SMTP_SSL) and 587/25 are STARTTLS; some networks block one but
    # not the other (e.g. an ISP blocking 587), so pick the mechanism the configured port expects
    # rather than assuming STARTTLS always.
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10, context=ssl.create_default_context()) as smtp:
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_FROM, [email], msg.as_string())
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_FROM, [email], msg.as_string())


def _issue_verification_code(email: str) -> str:
    """Generates a fresh 4-digit code, stores it, and emails it. Raises on SMTP failure so
    callers can decide how to surface that to the user."""
    code = f"{secrets.randbelow(10000):04d}"
    now = int(time.time())
    with db() as c:
        c.execute(
            "INSERT OR REPLACE INTO email_verifications (email, code, expires_ts, sent_ts, attempts) VALUES (?,?,?,?,0)",
            (email, code, now + VERIFICATION_CODE_TTL, now),
        )
    _send_verification_email(email, code)
    return code


def _create_session(user_id: int, email: str) -> str:
    token = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("INSERT INTO sessions (token, user_id, email, created_ts) VALUES (?,?,?,?)",
                  (token, user_id, email, int(time.time())))
    return token


def _user_public_dict(row) -> dict:
    return {
        "email": row["email"], "account_type": row["account_type"] or "individual",
        "first_name": row["first_name"], "last_name": row["last_name"],
        "job_title": row["job_title"], "company": row["company"],
        "birth_date": row["birth_date"], "employee_count": row["employee_count"],
    }


@app.post("/api/auth/signup")
def api_auth_signup():
    data = request.get_json(silent=True) or {}
    account_type = "organization" if data.get("account_type") == "organization" else "individual"
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    job_title = (data.get("job_title") or "").strip()
    company = (data.get("company") or "").strip()
    birth_date = (data.get("birth_date") or "").strip()
    employee_count = (data.get("employee_count") or "").strip()

    if not first_name or not last_name:
        return jsonify({"error": "First and last name are required."}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Enter a valid email address."}), 400
    if not PASSWORD_RE.match(password):
        return jsonify({"error": "Password needs 8+ characters, upper, lower, a number, and a symbol."}), 400

    if account_type == "organization":
        domain = email.rsplit("@", 1)[-1]
        if domain in PUBLIC_EMAIL_DOMAINS:
            return jsonify({"error": "Use a business email. Public email domains are not accepted."}), 400
        if not company:
            return jsonify({"error": "Organization name is required."}), 400
        if employee_count not in EMPLOYEE_COUNT_RANGES:
            return jsonify({"error": "Select an employee count range."}), 400

    with db() as c:
        if c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            return jsonify({"error": "An account with that email already exists."}), 409
        cur = c.execute(
            """INSERT INTO users
               (email, password_hash, account_type, first_name, last_name, job_title, company,
                birth_date, employee_count, created_ts)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (email, generate_password_hash(password), account_type, first_name, last_name,
             job_title or None, company or None, birth_date or None,
             employee_count if account_type == "organization" else None, int(time.time())),
        )
        user_id = cur.lastrowid

    if not _smtp_configured():
        # Roll back the account rather than leaving it permanently stuck unverified because the
        # server has no way to ever send it a code.
        with db() as c:
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
        return jsonify({"error": "Signup is temporarily unavailable: the server isn't configured to send verification emails."}), 500

    try:
        _issue_verification_code(email)
    except Exception as e:
        return jsonify({
            "error": "Account created, but the verification email couldn't be sent. Use \"Resend code\" to try again.",
            "pending_verification": True, "email": email,
        }), 202

    return jsonify({"pending_verification": True, "email": email})


@app.post("/api/auth/verify")
def api_auth_verify():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    with db() as c:
        vrow = c.execute("SELECT * FROM email_verifications WHERE email=?", (email,)).fetchone()
        if not vrow:
            return jsonify({"error": "No pending verification for this email. Request a new code."}), 400
        if int(time.time()) > vrow["expires_ts"]:
            return jsonify({"error": "That code expired. Request a new one."}), 400
        if vrow["attempts"] >= VERIFICATION_MAX_ATTEMPTS:
            return jsonify({"error": "Too many incorrect attempts. Request a new code."}), 429
        if code != vrow["code"]:
            c.execute("UPDATE email_verifications SET attempts=attempts+1 WHERE email=?", (email,))
            return jsonify({"error": "Incorrect code."}), 400

        c.execute("DELETE FROM email_verifications WHERE email=?", (email,))
        c.execute("UPDATE users SET email_verified=1 WHERE email=?", (email,))
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if not row:
        return jsonify({"error": "Account not found."}), 404
    token = _create_session(row["id"], email)
    return jsonify({"token": token, **_user_public_dict(row)})


@app.post("/api/auth/resend")
def api_auth_resend():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    with db() as c:
        user_row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user_row:
            return jsonify({"error": "Account not found."}), 404
        if user_row["email_verified"]:
            return jsonify({"error": "This account is already verified."}), 400
        vrow = c.execute("SELECT * FROM email_verifications WHERE email=?", (email,)).fetchone()
        if vrow and int(time.time()) - vrow["sent_ts"] < VERIFICATION_RESEND_COOLDOWN:
            wait = VERIFICATION_RESEND_COOLDOWN - (int(time.time()) - vrow["sent_ts"])
            return jsonify({"error": f"Please wait {wait}s before requesting another code."}), 429

    if not _smtp_configured():
        return jsonify({"error": "Server isn't configured to send verification emails."}), 500
    try:
        _issue_verification_code(email)
    except Exception:
        return jsonify({"error": "Couldn't send the email right now. Try again shortly."}), 502
    return jsonify({"ok": True, "email": email})


@app.post("/api/auth/login")
def api_auth_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    with db() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Incorrect email or password."}), 401

    if not row["email_verified"]:
        if _smtp_configured():
            try:
                _issue_verification_code(email)
            except Exception:
                pass
        return jsonify({"error": "Please verify your email first.", "pending_verification": True, "email": email}), 403

    token = _create_session(row["id"], email)
    return jsonify({"token": token, **_user_public_dict(row)})


@app.get("/api/auth/me")
def api_auth_me():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if not token:
        return jsonify({"error": "not authenticated"}), 401
    with db() as c:
        session_row = c.execute("SELECT email FROM sessions WHERE token=?", (token,)).fetchone()
        if not session_row:
            return jsonify({"error": "not authenticated"}), 401
        user_row = c.execute("SELECT * FROM users WHERE email=?", (session_row["email"],)).fetchone()
    if not user_row:
        return jsonify({"error": "not authenticated"}), 401
    return jsonify(_user_public_dict(user_row))


@app.post("/api/auth/logout")
def api_auth_logout():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if token:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
    return jsonify({"ok": True})


@app.get("/login")
def serve_login_page():
    # Served from the backend itself (rather than requiring the separate webapp/ static server)
    # so "Connect with PhishGuard" always has somewhere to open, as long as the backend is running.
    return send_from_directory(WEBAPP_DIR, "login.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
