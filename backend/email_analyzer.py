"""
PhishGuard AI — Email Header & Link Analyzer
Scores an email (headers + subject/snippet + links found in its body) for phishing risk.
Reuses the URL feature extractor / model so link risk is scored identically to a normal site scan.
"""
import re
from email.utils import parseaddr

from feature_extractor import BRAND_NAMES, brand_similarity

URGENT_PHRASES = [
    "verify your account", "account suspended", "act now", "click here immediately",
    "confirm your identity", "unusual activity", "your account will be closed",
    "urgent action required", "password will expire", "click below to verify",
    "limited time", "final notice", "security alert", "unauthorized login",
    "reset your password", "update your billing", "you have won", "claim your prize",
]

CREDENTIAL_REQUEST_PHRASES = [
    "password", "ssn", "social security", "credit card", "card number", "cvv",
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

    if auth["has_auth_header"]:
        if auth["spf"] not in ("pass",):
            score += 20; msg = f"SPF check {auth['spf']} — sender may be forged."
            reasons.append(msg); sender_bullets.append({"level": "critical", "text": msg})
        if auth["dkim"] not in ("pass",):
            score += 20; msg = f"DKIM check {auth['dkim']} — message integrity/signature not verified."
            reasons.append(msg); sender_bullets.append({"level": "critical", "text": msg})
        if auth["dmarc"] not in ("pass",):
            score += 15; msg = f"DMARC check {auth['dmarc']} — domain alignment failed."
            reasons.append(msg); sender_bullets.append({"level": "critical", "text": "DMARC failed."})
    else:
        score += 8; msg = "No authentication results found on this message."
        reasons.append(msg); sender_bullets.append({"level": "warning", "text": msg})

    if mismatch["reply_to_mismatch"]:
        score += 15; msg = "Reply-To domain differs from the From domain — replies go elsewhere."
        reasons.append(msg); sender_bullets.append({"level": "warning", "text": "Reply-To domain mismatch."})
    if mismatch["return_path_mismatch"]:
        score += 10; msg = "Return-Path domain differs from the From domain."
        reasons.append(msg); sender_bullets.append({"level": "warning", "text": "Return-Path domain mismatch."})
    if mismatch["display_name_brand_spoof"]:
        score += 25
        msg = (
            f"Display name references '{mismatch['spoofed_brand']}' but the sending domain "
            f"({mismatch['from_domain'] or 'unknown'}) doesn't match — likely impersonation."
        )
        reasons.append(msg)
        sender_bullets.append({"level": "critical", "text": f"Domain mismatch — impersonating '{mismatch['spoofed_brand']}'."})
    if not sender_bullets:
        sender_bullets.append({"level": "ok", "text": "Sender authentication and domains check out."})

    content_bullets = []
    if urgent_hits:
        score += min(20, urgent_hits * 7)
        msg = f"Subject/body uses {urgent_hits} urgency/pressure phrase(s) typical of phishing."
        reasons.append(msg); content_bullets.append({"level": "warning", "text": "Urgency detected."})
    if cred_hits:
        score += min(25, len(cred_hits) * 10)
        msg = f"Content requests sensitive info: {', '.join(cred_hits)}."
        reasons.append(msg); content_bullets.append({"level": "critical", "text": "Credential/sensitive-info request detected."})
    if not content_bullets:
        content_bullets.append({"level": "ok", "text": "No urgency or credential-request language detected."})

    # Score every link, keep the worst — and build URL-section bullets from it.
    link_results = []
    worst = None
    url_bullets = []
    for url in links or []:
        try:
            r = classify_url_fn(url)
        except Exception:
            continue
        link_results.append({"url": url, "verdict": r["verdict"], "risk_score": r["risk_score"]})
        if worst is None or r["risk_score"] > worst["risk_score"]:
            worst = r

    if worst:
        score = max(score, worst["risk_score"])
        if worst["risk_score"] >= 35:
            reasons.append(f"Contains a link scored {worst['risk_score']}/100 risk: {worst['url']}")
        url_bullets = worst.get("sections", {}).get("url", [])
    elif links:
        reasons.append(f"{len(links)} link(s) in the email, none flagged as risky.")
        url_bullets = [{"level": "ok", "text": f"{len(links)} link(s) scanned, none flagged."}]
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
    elif cred_hits or (worst and worst["risk_score"] >= 60):
        threat_type = "Credential Phishing"
    elif mismatch["display_name_brand_spoof"]:
        threat_type = "Brand Impersonation"
    elif mismatch["reply_to_mismatch"] or mismatch["return_path_mismatch"]:
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
