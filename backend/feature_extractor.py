"""
PhishGuard AI; Feature Extractor
Produces a fixed-length numeric feature vector for any URL.
Used both during model training and at inference time inside the Flask API.
"""
import re
import math
import socket
import difflib
from urllib.parse import urlparse, ParseResult
from datetime import datetime

import tldextract


def _safe_urlparse(url: str) -> ParseResult:
    """urlparse() raises ValueError on malformed input (e.g. stray '[' ']' that look like an
    IPv6 host literal); real-world scraped URL datasets are full of this. Since this runs both
    at training time over hundreds of thousands of rows and live on every extension scan, a
    malformed URL must degrade to a best-effort parse rather than crash the caller."""
    try:
        return urlparse(url)
    except ValueError:
        try:
            return urlparse(re.sub(r"[\[\]]", "", url))
        except ValueError:
            return ParseResult(scheme="http", netloc="", path=url, params="", query="", fragment="")

SUSPICIOUS_KEYWORDS = [
    # "account", "login", "signin", "secure", and "support" were removed from this list; they're
    # words major companies genuinely use in their own official domains (accounts.google.com,
    # login.microsoftonline.com, support.google.com, secure.bankofamerica.com are all real), so
    # matching on them alone was flagging legitimate sites, not just phishing. keyword_hits is
    # now the model's single most important feature (after path/url/query length were removed
    # for the same kind of over-generalization problem; see the FEATURE_NAMES comment below), so
    # a too-generic word here carries real weight.
    "verify","update","confirm","banking",
    "wallet","suspended","limited","unlock","billing","invoice",
    "password","appleid","paypal","amaz0n","g00gle","microsft","webscr",
]
SUSPICIOUS_TLDS = {"tk","ml","ga","cf","gq","xyz","top","click","loan","work","zip","mov"}
BRAND_NAMES = ["paypal","apple","google","microsoft","amazon","facebook","instagram","netflix","bank"]

# Real domains for common phishing-impersonation targets, used to detect lookalike/typosquat
# domains (e.g. "paypa1-secure.com" scored against "paypal.com").
BRAND_DOMAINS = {
    "paypal": "paypal.com", "apple": "apple.com", "google": "google.com",
    "microsoft": "microsoft.com", "amazon": "amazon.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "netflix": "netflix.com", "chase": "chase.com",
    "bankofamerica": "bankofamerica.com", "wellsfargo": "wellsfargo.com",
    "dhl": "dhl.com", "usps": "usps.com", "linkedin": "linkedin.com",
}


def registrable_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    ext = tldextract.extract(url)
    return ".".join(p for p in [ext.domain, ext.suffix] if p)


def brand_similarity(url: str) -> dict | None:
    """Best-matching known brand by string similarity, if the URL isn't actually that brand's
    real domain; flags lookalike/typosquat domains (e.g. paypa1-secure-login.tk vs paypal.com).
    Compares each hyphen-separated token of the domain label against each brand name, so a
    typosquat buried in a longer domain (paypa1-secure-login) still scores against "paypal"
    rather than being diluted by comparing the whole string to "paypal.com"."""
    domain = registrable_domain(url)
    if not domain:
        return None
    ext = tldextract.extract(domain)
    label = ext.domain.lower()
    tokens = set(re.split(r"[-_]", label)) | {label}

    best = None
    best_ratio = 0.0
    for brand, real_domain in BRAND_DOMAINS.items():
        if domain == real_domain:
            return None  # it IS the real domain, not a lookalike
        for tok in tokens:
            if not tok:
                continue
            ratio = difflib.SequenceMatcher(None, tok, brand).ratio()
            if ratio >= 0.72 and ratio > best_ratio:
                best_ratio = ratio
                best = {"brand": brand, "real_domain": real_domain, "domain": domain, "similarity": round(ratio * 100)}
    return best


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


# Ordered list of feature names; keep stable; the model is trained on this exact order.
#
# path_length, query_length, and url_length are deliberately excluded despite still being
# computed in extract_features() below. Across three retraining rounds, length-based features
# kept dominating the model (path_length hit ~32% importance; after removing it, url_length,
# which is mostly just path length in another form since it includes the path, immediately
# took over at ~20%) purely because of *which dataset each class happened to be scraped from*,
# not a real causal link to phishing. A broad real-world sweep (github.com/openai, BBC News,
# Netflix, Gmail, LinkedIn, Python's own docs, ...) kept landing as suspicious/phishing at high
# confidence purely for having an ordinary, moderately-long URL. That's a dataset-artifact
# confound, not a signal. host_length is kept; hostname length is a more genuinely meaningful
# signal (long/random subdomains are a real phishing tell) and never showed this problem.
FEATURE_NAMES = [
    "host_length",
    "num_dots","num_hyphens","num_digits","num_special",
    "uses_https","uses_ip_host","has_at_symbol","has_double_slash_in_path",
    "subdomain_depth","tld_suspicious","punycode","host_entropy",
    "keyword_hits","brand_in_subdomain","port_explicit","has_redirect_in_url",
    "brand_similarity_score","is_brand_lookalike",
]


def extract_features(url: str, page_features: dict | None = None) -> dict:
    """Return both the numeric feature vector and human-readable explanations."""
    if not url.startswith(("http://","https://")):
        url = "http://" + url
    p = _safe_urlparse(url)
    try:
        host = p.hostname or ""
    except ValueError:
        host = ""  # malformed netloc (e.g. bad IPv6 brackets) even after _safe_urlparse's retry
    ext = tldextract.extract(url)
    tld = ext.suffix.lower()
    subdomain = ext.subdomain.lower()
    full = url.lower()

    f = {}
    f["url_length"] = len(url)
    f["host_length"] = len(host)
    f["path_length"] = len(p.path)
    f["query_length"] = len(p.query)
    f["num_dots"] = url.count(".")
    f["num_hyphens"] = host.count("-")
    f["num_digits"] = sum(c.isdigit() for c in host)
    f["num_special"] = sum(1 for c in url if c in "?=&%@_~+")
    f["uses_https"] = int(p.scheme == "https")
    f["uses_ip_host"] = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)))
    f["has_at_symbol"] = int("@" in url)
    f["has_double_slash_in_path"] = int("//" in p.path)
    f["subdomain_depth"] = subdomain.count(".") + (1 if subdomain else 0)
    f["tld_suspicious"] = int(tld in SUSPICIOUS_TLDS)
    f["punycode"] = int("xn--" in host)
    f["host_entropy"] = round(shannon_entropy(host.replace(".","")), 3)
    f["keyword_hits"] = sum(1 for k in SUSPICIOUS_KEYWORDS if k in full)
    f["brand_in_subdomain"] = int(any(b in subdomain for b in BRAND_NAMES))
    try:
        f["port_explicit"] = int(p.port is not None)
    except ValueError:
        f["port_explicit"] = 0  # malformed port (e.g. non-numeric); treat as absent
    f["has_redirect_in_url"] = int("//" in url[8:])  # double slash after scheme

    # brand_similarity was already computed for the UI (explanations/threat-type) but never fed
    # to the trained model itself; a real typosquat/lookalike signal the classifier couldn't see.
    sim = brand_similarity(url)
    f["brand_similarity_score"] = sim["similarity"] if sim else 0
    f["is_brand_lookalike"] = int(sim is not None)
    return f


def to_vector(features: dict) -> list[float]:
    return [features[name] for name in FEATURE_NAMES]


def build_url_sections(features: dict, url: str) -> list[dict]:
    """Investigation-report bullets for the URL: {level: critical|warning|ok, text}."""
    bullets = []
    if features["uses_ip_host"]:
        bullets.append({"level": "critical", "text": "Hostname is a raw IP address."})
    if features["tld_suspicious"]:
        bullets.append({"level": "critical", "text": "Suspicious top-level domain (high-abuse list)."})
    sim = brand_similarity(url)
    if sim:
        bullets.append({
            "level": "critical" if sim["similarity"] >= 85 else "warning",
            "text": f"Domain similarity: {sim['similarity']}% match to {sim['real_domain']} ({sim['brand']}); likely lookalike.",
        })
    if features["has_at_symbol"] or features["has_double_slash_in_path"]:
        bullets.append({"level": "warning", "text": "Redirect detected (@ or // trick in URL)."})
    if not features["uses_https"]:
        bullets.append({"level": "warning", "text": "No HTTPS; traffic isn't encrypted."})
    if features["punycode"]:
        bullets.append({"level": "warning", "text": "Punycode/internationalized domain; may visually impersonate a real brand."})
    if features["subdomain_depth"] >= 3:
        bullets.append({"level": "warning", "text": "Excessive subdomains hide the real registrable domain."})
    if features["keyword_hits"] >= 2:
        bullets.append({"level": "warning", "text": f"{features['keyword_hits']} high-risk keywords in the URL (verify/login/secure/etc)."})
    if features["host_entropy"] > 4.0:
        bullets.append({"level": "warning", "text": "Hostname looks randomly generated."})
    if not bullets:
        bullets.append({"level": "ok", "text": "No suspicious URL indicators detected."})
    return bullets


def classify_threat_type(features: dict, url: str, credential_content: bool = False) -> str:
    sim = brand_similarity(url)
    if credential_content and (features["keyword_hits"] >= 1 or sim or features["uses_ip_host"]):
        return "Credential Phishing"
    if sim:
        return "Brand Impersonation"
    if features["has_at_symbol"] or features["has_double_slash_in_path"]:
        return "Redirect / Cloaking"
    if features["keyword_hits"] >= 2:
        return "Credential Phishing"
    if features["uses_ip_host"] or features["tld_suspicious"] or features["host_entropy"] > 4.0:
        return "Suspicious Link"
    return "Low Risk"


def build_explanations(features: dict, url: str) -> list[str]:
    # Kept short and concrete on purpose (e.g. "Overly long URL", not a full sentence); these
    # show up in notification popups with limited space, not just a detail panel.
    out = []
    if not features["uses_https"]:
        out.append("No HTTPS")
    if features["uses_ip_host"]:
        out.append("Raw IP address host")
    if features["tld_suspicious"]:
        out.append("Suspicious top-level domain")
    if features["punycode"]:
        out.append("Punycode domain")
    if features["subdomain_depth"] >= 3:
        out.append("Excessive subdomains")
    if features["brand_in_subdomain"]:
        out.append("Brand name in subdomain")
    if features["keyword_hits"] >= 2:
        out.append(f"{features['keyword_hits']} high-risk keywords")
    if features["has_at_symbol"] or features["has_double_slash_in_path"]:
        out.append("Redirect trick in URL")
    if features["url_length"] > 100:
        out.append("Overly long URL")
    if features["host_entropy"] > 4.0:
        out.append("Random-looking hostname")
    if not out:
        out.append("No phishing indicators detected")
    return out
