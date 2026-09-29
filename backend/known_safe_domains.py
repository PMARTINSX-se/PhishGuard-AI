"""
Curated allowlist of unambiguous, major real-world domains; a safety net on top of the ML
model, not a replacement for it. Deliberately narrow: only the root organization itself (and its
official subdomains), never generic hosting/blogging/link-shortener platforms (blogspot.com,
weebly.com, bit.ly, etc.) where anyone can host arbitrary content, including phishing.

A match here short-circuits straight to "safe" before the model ever runs; for a domain on this
list, that's the right call: the phishing risk on accounts.google.com or www.amazon.com is
effectively zero, and no URL-string classifier should ever need to "prove" that. This exists
because the model was flagging exactly these domains as phishing due to a dataset bias toward
short/simple URLs in its training "safe" class; see the comment above FEATURE_NAMES in
feature_extractor.py for the full history.
"""
import tldextract

KNOWN_SAFE_DOMAINS = {
    # Search / tech giants
    "google.com", "youtube.com", "gmail.com", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "googlevideo.com", "android.com", "chrome.com",
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
    "outlook.com", "msn.com", "bing.com", "azure.com", "windows.com", "xbox.com",
    "apple.com", "icloud.com", "itunes.com", "amazon.com", "aws.amazon.com", "amazonaws.com",
    "meta.com", "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "x.com", "twitter.com", "linkedin.com", "pinterest.com", "snapchat.com", "tiktok.com",
    "reddit.com", "discord.com", "slack.com", "zoom.us", "dropbox.com", "box.com",
    "adobe.com", "salesforce.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
    "cisco.com", "vmware.com", "sap.com", "shopify.com", "squarespace.com", "wordpress.com",
    "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "stackoverflow.com",
    "atlassian.com", "notion.so", "figma.com", "canva.com", "asana.com", "trello.com",
    "hubspot.com", "mailchimp.com", "zendesk.com", "stripe.com", "twilio.com", "cloudflare.com",
    "digitalocean.com", "heroku.com", "vercel.com", "netlify.com",

    # AI / research
    "openai.com", "anthropic.com", "huggingface.co", "deepmind.com",

    # Media / entertainment / news
    "netflix.com", "spotify.com", "hulu.com", "disneyplus.com", "twitch.tv", "vimeo.com",
    "soundcloud.com", "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "reuters.com",
    "theguardian.com", "washingtonpost.com", "wsj.com", "bloomberg.com", "forbes.com",
    "npr.org", "apnews.com", "espn.com", "imdb.com",

    # Reference / education / government
    "wikipedia.org", "wikimedia.org", "archive.org", "coursera.org", "edx.org", "khanacademy.org",
    "mit.edu", "stanford.edu", "harvard.edu", "usa.gov", "irs.gov", "ssa.gov", "usps.com",
    "whitehouse.gov", "gov.uk", "europa.eu", "who.int", "un.org",

    # Retail / travel / payments
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "costco.com", "aliexpress.com",
    "etsy.com", "airbnb.com", "booking.com", "expedia.com", "uber.com", "lyft.com",
    "doordash.com", "paypal.com", "venmo.com", "visa.com", "mastercard.com",

    # Major banks (US/UK/global; the specific institutions themselves, not lookalikes)
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "citi.com",
    "capitalone.com", "usbank.com", "pnc.com", "americanexpress.com", "discover.com",
    "hsbc.com", "barclays.co.uk", "natwest.com", "lloydsbank.com", "santander.com",
}


def _registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return ext.registered_domain.lower()


def is_known_safe_domain(url: str) -> bool:
    return _registered_domain(url) in KNOWN_SAFE_DOMAINS
