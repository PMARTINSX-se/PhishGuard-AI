"""
PhishGuard AI — Live Network Deep-Check
Adds real network signals on top of the static URL-string model: TLS certificate age/validity,
WHOIS domain age, redirect-chain following, and live page-content analysis (credential forms,
brand impersonation). Deliberately NOT run on every automatic tab-visit scan — it's slow (network
round trips) and only wired up for manual/important scans (Rescan button, webapp scanner, email
links). See classify(url, deep=True) in app.py.
"""
import concurrent.futures
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois
from bs4 import BeautifulSoup

from feature_extractor import BRAND_DOMAINS, registrable_domain

TOTAL_BUDGET_S = 8
NEW_CERT_DAYS = 14          # cert issued this recently is a strong phishing signal
NEW_DOMAIN_DAYS = 30        # domain registered this recently is a strong phishing signal
YOUNG_DOMAIN_DAYS = 180     # softer signal


# ---------- SSRF guard ----------
def _is_public_host(hostname: str) -> bool:
    """Reject scanning anything that resolves to a private/loopback/link-local/reserved address —
    this backend fetches whatever URL a user pastes, a visited page links to, or an email
    contains, so it must never become a proxy for probing internal networks or cloud metadata
    endpoints (169.254.169.254 etc)."""
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
            return False
    return True


# ---------- TLS certificate ----------
def check_tls(host: str, timeout: float = 4.0) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()

    def _parse(field):
        # e.g. "Jan  1 00:00:00 2024 GMT"
        return datetime.strptime(field, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    not_before = _parse(cert["notBefore"])
    not_after = _parse(cert["notAfter"])
    now = datetime.now(timezone.utc)
    age_days = (now - not_before).days
    days_until_expiry = (not_after - now).days
    issuer = dict(x[0] for x in cert.get("issuer", []))

    return {
        "ok": True,
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "unknown",
        "not_before": cert["notBefore"],
        "not_after": cert["notAfter"],
        "age_days": age_days,
        "days_until_expiry": days_until_expiry,
    }


# ---------- WHOIS domain age ----------
def check_domain_age(domain: str, timeout: float = 4.0) -> dict:
    def _lookup():
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        return created

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_lookup)
        created = fut.result(timeout=timeout)

    if not created:
        return {"ok": True, "age_days": None}
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - created).days
    return {"ok": True, "age_days": age_days, "created": str(created)}


# ---------- redirect chain + page content ----------
def fetch_and_analyze(url: str, timeout: float = 6.0, max_bytes: int = 300_000) -> dict:
    resp = requests.get(
        url, timeout=timeout, allow_redirects=True, stream=True,
        headers={"User-Agent": "Mozilla/5.0 (PhishGuard AI safety scanner)"},
    )
    chunks, total = [], 0
    for chunk in resp.iter_content(chunk_size=8192):
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    html = b"".join(chunks).decode(resp.encoding or "utf-8", errors="ignore")

    redirect_domains = [registrable_domain(r.url) for r in resp.history] + [registrable_domain(resp.url)]
    original_domain = registrable_domain(url)
    hopped = bool(redirect_domains and redirect_domains[-1] != original_domain)

    soup = BeautifulSoup(html, "html.parser")
    has_password_field = bool(soup.find("input", {"type": re.compile("^password$", re.I)}))

    cross_domain_form = False
    final_domain = registrable_domain(resp.url)
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        if action.startswith(("http://", "https://")):
            action_domain = registrable_domain(action)
            if action_domain and action_domain != final_domain:
                cross_domain_form = True
                break

    title = (soup.title.string if soup.title and soup.title.string else "").strip().lower()
    brand_mismatch = None
    for brand, real_domain in BRAND_DOMAINS.items():
        if brand in title and final_domain != real_domain:
            brand_mismatch = {"brand": brand, "real_domain": real_domain}
            break

    return {
        "ok": True,
        "status_code": resp.status_code,
        "final_url": resp.url,
        "redirect_count": len(resp.history),
        "domain_hopped": hopped,
        "has_password_field": has_password_field,
        "cross_domain_form": cross_domain_form,
        "brand_mismatch": brand_mismatch,
    }


# ---------- orchestration ----------
def live_check(url: str) -> dict:
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    bullets = []
    signals = {}
    score_delta = 0

    if not _is_public_host(host):
        return {
            "signals": {"skipped": True, "reason": "not a public host"},
            "bullets": [{"level": "ok", "text": "Live checks skipped — target is not a publicly reachable host."}],
            "score_delta": 0,
        }

    domain = registrable_domain(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            "tls": ex.submit(check_tls, host),
            "domain_age": ex.submit(check_domain_age, domain),
            "content": ex.submit(fetch_and_analyze, url),
        }
        done, not_done = concurrent.futures.wait(futures.values(), timeout=TOTAL_BUDGET_S)
        results = {}
        for name, fut in futures.items():
            if fut in done:
                try:
                    results[name] = fut.result()
                except Exception as e:
                    results[name] = {"ok": False, "error": str(e)}
            else:
                results[name] = {"ok": False, "error": "timed out"}

    # --- domain age (computed first — TLS cert freshness is only meaningful relative to it) ---
    age = results["domain_age"]
    signals["domain_age"] = age
    domain_age_days = age.get("age_days") if age.get("ok") else None
    domain_is_old = domain_age_days is not None and domain_age_days > YOUNG_DOMAIN_DAYS
    domain_is_new = domain_age_days is not None and domain_age_days <= NEW_DOMAIN_DAYS

    if domain_age_days is not None:
        if domain_is_new:
            score_delta += 25
            bullets.append({"level": "critical", "text": f"Domain registered only {domain_age_days} day(s) ago — brand-new domains are heavily favored by phishing campaigns."})
        elif domain_age_days <= YOUNG_DOMAIN_DAYS:
            score_delta += 10
            bullets.append({"level": "warning", "text": f"Domain is only {domain_age_days} days old."})

    # --- TLS ---
    # A freshly-issued cert on its own means almost nothing — modern CAs (Let's Encrypt etc.)
    # issue certs valid for only ~90 days, so every HTTPS site renews on a rolling basis
    # regardless of age. It only becomes a meaningful signal alongside a young/unverifiable
    # domain (a legit multi-year-old domain renewing its cert is normal and gets no flag at all).
    tls = results["tls"]
    signals["tls"] = tls
    if tls.get("ok"):
        if tls["age_days"] <= NEW_CERT_DAYS and not domain_is_old:
            if domain_is_new:
                score_delta += 15
                bullets.append({"level": "critical", "text": f"TLS certificate issued only {tls['age_days']} day(s) ago on a domain registered only {domain_age_days} day(s) ago — fresh cert + fresh domain is a strong phishing-kit pattern."})
            else:
                score_delta += 8
                bullets.append({"level": "warning", "text": f"TLS certificate issued only {tls['age_days']} day(s) ago and domain age couldn't be verified."})
        if tls["days_until_expiry"] < 0:
            score_delta += 10
            bullets.append({"level": "warning", "text": "TLS certificate has expired."})
    else:
        bullets.append({"level": "warning", "text": "Could not establish a secure connection to verify the certificate."})
        score_delta += 8

    # --- redirect + content ---
    content = results["content"]
    signals["content"] = content
    if content.get("ok"):
        if content.get("domain_hopped"):
            score_delta += 12
            bullets.append({"level": "warning", "text": f"URL redirects to a different domain ({content['final_url']})."})
        if content.get("has_password_field"):
            score_delta += 10
            bullets.append({"level": "warning", "text": "Page contains a password input field."})
        if content.get("cross_domain_form"):
            score_delta += 25
            bullets.append({"level": "critical", "text": "Page has a form that submits data to a different domain than the page itself — classic credential-harvesting pattern."})
        if content.get("brand_mismatch"):
            bm = content["brand_mismatch"]
            score_delta += 25
            bullets.append({"level": "critical", "text": f"Page title references '{bm['brand']}' but isn't hosted on {bm['real_domain']} — likely impersonation."})
    else:
        bullets.append({"level": "warning", "text": "Could not fetch the page to inspect its content."})

    if not bullets:
        bullets.append({"level": "ok", "text": "Live checks (TLS, domain age, page content) found nothing suspicious."})

    return {"signals": signals, "bullets": bullets, "score_delta": min(60, score_delta)}
