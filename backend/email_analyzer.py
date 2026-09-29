"""
PhishGuard AI; Email Header & Link Analyzer
Scores an email (headers + subject/snippet + links found in its body) for phishing risk.
Reuses the URL feature extractor / model so link risk is scored identically to a normal site scan.
"""
import re
from email.utils import parseaddr

from urllib.parse import urlparse

from feature_extractor import BRAND_NAMES, brand_similarity, registrable_domain

_RESOURCE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
)
_RESOURCE_HOSTS = {"fonts.googleapis.com", "fonts.gstatic.com"}

# Official sending domains that merely *resemble* a brand's main domain. Without this,
# Facebook's real notification domain (facebookmail.com) reads as a "lookalike" of facebook.com.
_OFFICIAL_MAIL_DOMAINS = {
    "facebookmail.com", "instagram.com", "amazonses.com", "microsoftonline.com",
    "accountprotection.microsoft.com", "paypal.com", "linkedin.com", "mail.instagram.com",
}


def _is_resource_url(url: str) -> bool:
    """Fonts, images, stylesheets, scripts; things a mail client loads, not links a person
    clicks. (The extension now only extracts <a href> links, but this also protects against
    older stored scans / other callers sending everything they found in the HTML.)"""
    try:
        p = urlparse(url)
    except ValueError:
        return False
    return (p.hostname or "").lower() in _RESOURCE_HOSTS or p.path.lower().endswith(_RESOURCE_EXTENSIONS)


def _is_strong_link_signal(result: dict, trust_brand_similarity: bool = True) -> bool:
    """Evidence solid enough to decide a verdict on its own, unlike the raw model probability
    (which is unreliable on tracking/redirect links). Strong means: a confirmed PhishTank or
    blacklist hit, or a *critical* finding; raw-IP host, high-abuse TLD, a lookalike of a known
    brand, or a critical live-check result (e.g. a password form posting to another domain).

    Brand-lookalike matches are only trusted when the sender isn't already authenticated as
    who they claim to be: it's a heuristic that fires on legitimate hyphenated names such as
    google-analytics.com, so for a cleanly-authenticated sender it isn't enough by itself."""
    threat = result.get("threat_type") or ""
    if "PhishTank" in threat or threat == "Blacklisted":
        return True
    for b in (result.get("sections") or {}).get("url", []):
        if b.get("level") != "critical":
            continue
        if b.get("text", "").startswith("Domain similarity") and not trust_brand_similarity:
            continue
        return True
    return False

URGENT_PHRASES = [
    # "reset your password", "security alert", "unusual activity", "unauthorized login",
    # "confirm your identity", "urgent action required", "password will expire", and "verify
    # your account" were removed; these are the *standard, legitimate* wording real security
    # systems use (Google/Microsoft "Security alert: new sign-in", real fraud-alert emails
    # literally say "unusual activity", real password-reset emails are titled "Reset your
    # password"). Flagging them meant an authentic, important security email a user should
    # actually read was getting marked as phishing. What's left leans toward phrasing that's
    # distinctly phishing-pretext (fake urgency/reward bait), not standard account-security language.
    "account suspended", "act now", "click here immediately",
    "your account will be closed", "click below to verify",
    "limited time", "final notice", "update your billing", "you have won", "claim your prize",
]

CREDENTIAL_REQUEST_PHRASES = [
    # Bare "password" was removed; it matches completely ordinary, benign notification email
    # ("your password was changed successfully", "your password expires in 30 days") just as
    # readily as an actual request for it. These phrases require request-style context instead.
    "enter your password", "confirm your password", "verify your password", "re-enter your password",
    "ssn", "social security", "credit card", "card number", "cvv",
    "account number", "routing number", "login credentials", "one-time code",
    "otp", "pin number", "security question", "date of birth",
]


def _domain(addr: str) -> str:
    _, email = parseaddr(addr or "")
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[-1].lower().strip()


def _registrable(domain: str) -> str:
    """Best-effort: last two labels (example.com out of mail.example.com)."""
    parts = [p for p in domain.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def parse_auth_results(headers: dict) -> dict:
    """Pull spf/dkim/dmarc verdicts out of an Authentication-Results header."""
    raw = ""
    for k, v in (headers or {}).items():
        if k.lower() == "authentication-results":
            raw = (raw + " " + str(v)) if raw else str(v)
    raw = raw.lower()

    def verdict_for(name):
        m = re.search(rf"{name}=([a-z]+)", raw)
        return m.group(1) if m else "none"

    return {
        "spf": verdict_for("spf"),
        "dkim": verdict_for("dkim"),
        "dmarc": verdict_for("dmarc"),
        "has_auth_header": bool(raw),
    }


def header_mismatch_signals(headers: dict) -> dict:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    from_addr = h.get("from", "")
    reply_to = h.get("reply-to", "")
    return_path = h.get("return-path", "")

    from_domain = _registrable(_domain(from_addr))
    reply_domain = _registrable(_domain(reply_to))
    return_domain = _registrable(_domain(return_path))

    display_name, _ = parseaddr(from_addr)
    display_name_l = display_name.lower()
    brand_hit = next((b for b in BRAND_NAMES if b in display_name_l), None)
    brand_spoof = bool(brand_hit and from_domain and brand_hit not in from_domain)

    return {
        "from_domain": from_domain,
        "reply_to_mismatch": bool(reply_domain and reply_domain != from_domain),
        "return_path_mismatch": bool(return_domain and return_domain != from_domain),
        "display_name_brand_spoof": brand_spoof,
        "spoofed_brand": brand_hit,
    }


def urgent_language_score(subject: str, snippet: str) -> int:
    text = f"{subject or ''} {snippet or ''}".lower()
    return sum(1 for p in URGENT_PHRASES if p in text)


def credential_request_hits(subject: str, snippet: str) -> list:
    text = f"{subject or ''} {snippet or ''}".lower()
    return [p for p in CREDENTIAL_REQUEST_PHRASES if p in text]


def classify_email(headers: dict, links: list, subject: str, snippet: str, classify_url_fn) -> dict:
    """
    classify_url_fn: callable(url) -> the same dict shape returned by app.classify() for a single URL.
    Combines header-based signals with the worst-scoring link into one verdict, and builds an
    investigation-report breakdown (sender/url/content sections + threat type) alongside it.
    """
    auth = parse_auth_results(headers)
    mismatch = header_mismatch_signals(headers)
    urgent_hits = urgent_language_score(subject, snippet)
    cred_hits = credential_request_hits(subject, snippet)

    score = 0
    reasons = []
    sender_bullets = []

    auth_fully_passed = auth["has_auth_header"] and auth["spf"] == "pass" and auth["dkim"] == "pass" and auth["dmarc"] == "pass"

    # `reasons` stays short (e.g. "SPF fail"); it feeds notification popups with limited space.
    # `sender_bullets`/`content_bullets` can carry the fuller explanation since the investigation
    # report has room for it.
    # "none" (the sender's domain simply publishes no SPF/DKIM/DMARC record) is NOT the same as
    # "fail" (a check ran and the message didn't verify; the actual sign of forgery). Small
    # senders routinely lack a record; treating that like a forgery gave a legitimate sender 35
    # points from authentication alone. Failures keep their full weight; absence is a mild flag.
    def _auth_check(name, label, fail_pts, none_pts, fail_text):
        nonlocal score
        val = auth[name]
        if val == "pass":
            return
        if val in ("none", "neutral"):
            score += none_pts; reasons.append(f"No {label} record")
            sender_bullets.append({"level": "warning", "text": f"{label} not configured for the sender's domain."})
        else:
            score += fail_pts; reasons.append(f"{label} {val}")
            sender_bullets.append({"level": "critical", "text": fail_text})

    if auth["has_auth_header"]:
        _auth_check("spf", "SPF", 20, 6, f"SPF check {auth['spf']}; sender may be forged.")
        _auth_check("dkim", "DKIM", 20, 6, f"DKIM check {auth['dkim']}; signature not verified.")
        _auth_check("dmarc", "DMARC", 15, 5, "DMARC failed.")
    else:
        score += 8; reasons.append("No auth results")
        sender_bullets.append({"level": "warning", "text": "No authentication results found on this message."})

    # Reply-To/Return-Path differing from From is completely normal for legitimate bulk mail sent
    # through an ESP (Mailchimp, SendGrid, Amazon SES, etc.); bounce-handling infrastructure
    # (VERP) intentionally uses a different domain, and that's exactly what SPF/DKIM/DMARC exist
    # to vouch for. Only treat the mismatch as a real signal when real authentication *didn't*
    # already pass; otherwise this was flagging huge amounts of ordinary newsletter/receipt/
    # notification email that any legitimate company sends through third-party infrastructure.
    if not auth_fully_passed:
        if mismatch["reply_to_mismatch"]:
            score += 15; reasons.append("Reply-To mismatch")
            sender_bullets.append({"level": "warning", "text": "Reply-To domain differs from From; replies go elsewhere."})
        if mismatch["return_path_mismatch"]:
            score += 10; reasons.append("Return-Path mismatch")
            sender_bullets.append({"level": "warning", "text": "Return-Path domain differs from From."})
    if mismatch["display_name_brand_spoof"]:
        score += 25
        reasons.append(f"Impersonating {mismatch['spoofed_brand']}")
        sender_bullets.append({"level": "critical", "text": f"Domain mismatch; impersonating '{mismatch['spoofed_brand']}'."})
    if not sender_bullets:
        sender_bullets.append({"level": "ok", "text": "Sender authentication and domains check out."})

    content_bullets = []
    if urgent_hits:
        score += min(20, urgent_hits * 7)
        reasons.append(f"{urgent_hits} urgency phrase(s)")
        content_bullets.append({"level": "warning", "text": "Urgency detected."})
    if cred_hits:
        score += min(25, len(cred_hits) * 10)
        reasons.append("Requests sensitive info")
        content_bullets.append({"level": "critical", "text": f"Requests sensitive info: {', '.join(cred_hits)}."})
    if not content_bullets:
        content_bullets.append({"level": "ok", "text": "No urgency or credential-request language detected."})

    # ---- links ----
    # Which links are worth scoring at all: drop non-clickable resources (fonts/images/CSS), and
    # (only when the sender's authentication fully passed, so the From domain can be trusted)
    # links back to the sender's own domain. Then score at most a few per domain: legitimate
    # bulk mail repeats the same tracking link dozens of times.
    from_domain = registrable_domain("http://" + _domain(headers.get("From") or headers.get("from") or "")) if headers else ""
    # An attacker can register a lookalike domain (paypa1-secure.com) and authenticate *it*, so a
    # passing SPF/DKIM/DMARC only vouches for "this really is that domain"; not that the domain
    # is who it pretends to be. Never treat a lookalike/brand-spoofing sender's own links as safe.
    sender_is_lookalike = bool(
        from_domain and from_domain not in _OFFICIAL_MAIL_DOMAINS and brand_similarity("http://" + from_domain)
    )
    trust_sender = auth_fully_passed and not sender_is_lookalike and not mismatch["display_name_brand_spoof"]
    candidates = []
    per_domain = {}
    for url in links or []:
        if _is_resource_url(url):
            continue
        dom = registrable_domain(url)
        if trust_sender and from_domain and dom == from_domain:
            continue
        per_domain[dom] = per_domain.get(dom, 0) + 1
        if per_domain[dom] <= 2 and len(candidates) < 8:
            candidates.append(url)

    link_results = []
    worst = None
    strong_hit = None
    url_bullets = []
    for url in candidates:
        try:
            r = classify_url_fn(url)
        except Exception:
            continue
        link_results.append({"url": url, "verdict": r["verdict"], "risk_score": r["risk_score"]})
        if worst is None or r["risk_score"] > worst["risk_score"]:
            worst = r
        if _is_strong_link_signal(r, trust_brand_similarity=not trust_sender) and (
            strong_hit is None or r["risk_score"] > strong_hit["risk_score"]
        ):
            strong_hit = r

    if strong_hit:
        # Authoritative evidence (PhishTank match, blacklist, or a critical live-check finding
        # such as a cross-domain password form); this alone is allowed to decide the verdict.
        score = max(score, strong_hit["risk_score"])
        reasons.append(f"Risky link ({strong_hit['risk_score']}/100)")
    elif worst and worst["risk_score"] >= 35:
        # Model-only score on a link. The URL model is not reliable on tracking/redirect links
        # (long random tokens look "phishy"; Facebook and Railway notification links scored
        # 90-100), so on its own it only nudges the score, and barely at all when the sender
        # authenticated cleanly. It can no longer single-handedly make an email "phishing".
        cap = 8 if trust_sender else 25
        bump = min(cap, (worst["risk_score"] - 30) // 2)
        score += bump
        if not trust_sender:
            reasons.append(f"Suspicious link ({worst['risk_score']}/100)")

    # Impersonating a brand *and* asking for credentials/payment details is the textbook
    # phishing combination; each alone is only suspicious, together they corroborate.
    if cred_hits and (mismatch["display_name_brand_spoof"] or sender_is_lookalike):
        score += 15
        reasons.append("Impersonation + credential request")

    if worst:
        url_bullets = (strong_hit or worst).get("sections", {}).get("url", [])
    elif links:
        url_bullets = [{"level": "ok", "text": f"{len(links)} link(s) found, none needed scoring."}]
    else:
        url_bullets = [{"level": "ok", "text": "No links found in this email."}]

    score = min(100, score)
    if score >= 70:
        verdict, recommendation = "phishing", "Do not click links or provide credentials."
    elif score >= 35:
        verdict, recommendation = "suspicious", "Verify the sender through a separate channel before acting."
    else:
        verdict, recommendation = "safe", "Proceed"

    if not reasons:
        reasons.append("No phishing indicators detected in this email.")

    # Threat type: pick the most specific applicable label.
    if verdict == "safe":
        threat_type = "None"
    elif cred_hits or strong_hit:
        threat_type = "Credential Phishing"
    elif mismatch["display_name_brand_spoof"]:
        threat_type = "Brand Impersonation"
    elif not auth_fully_passed and (mismatch["reply_to_mismatch"] or mismatch["return_path_mismatch"]):
        threat_type = "Spoofed Sender"
    elif urgent_hits:
        threat_type = "Social Engineering / Scam"
    else:
        threat_type = "Suspicious Email"

    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
        "recommendation": recommendation,
        "links": link_results,
        "auth": auth,
        "threat_type": threat_type,
        "sections": {"sender": sender_bullets, "url": url_bullets, "content": content_bullets},
    }
