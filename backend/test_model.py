"""Quick sanity tests for the trained model + feature extractor."""
import joblib
import numpy as np
from feature_extractor import extract_features, to_vector

CASES = [
    ("https://www.google.com", "safe"),
    ("https://github.com/openai", "safe"),
    ("http://paypa1-secure-login.tk/verify", "phishing"),
    ("http://192.168.4.21/banking/login", "phishing"),
    ("http://amaz0n-account-update.xyz/confirm", "phishing"),
]

# Regression cases for the "long/complex-but-genuinely-safe URL scored as phishing" bug: the
# static model's training data skewed toward short, simple "safe" URLs, so real long/parameter-
# heavy URLs on major sites (search results, watch pages, product pages, OAuth flows) scored as
# phishing. These are all on the known-safe-domains allowlist (app.classify), so they should be
# "safe" at risk_score 0 regardless of what the static model alone would say. Checked separately
# from CASES above because these exercise app.classify(), not the raw model.
REAL_WORLD_SAFE_CASES = [
    "https://www.amazon.com/gp/product/B08N5WRWNW/ref=ppx_yo_dt_b_asin_title_o00_s00?ie=UTF8&psc=1&th=1",
    "https://www.google.com/search?q=phishguard+ai+extension+chrome&sxsrf=ALiCzsZ&source=hp&ei=abc123def456",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLxyz123&index=5&t=42s&ab_channel=RickAstley",
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&redirect_uri=https%3A%2F%2Fexample.com&response_type=code&scope=email",
    "https://www.linkedin.com/in/satyanadella/recent-activity/all/?originalSubdomain=uk",
]


def main():
    bundle = joblib.load("models/phishing_rf.pkl")
    model = bundle["model"]
    correct = 0
    for url, expected in CASES:
        vec = np.array([to_vector(extract_features(url))])
        prob = model.predict_proba(vec)[0][1]
        verdict = "phishing" if prob >= 0.5 else "safe"
        # Plain ASCII; Windows' console defaults to cp1252, which can't encode "✓"/"✗" and
        # would otherwise crash this print outright (train_model.py had the same bug).
        ok = "PASS" if verdict == expected else "FAIL"
        if verdict == expected: correct += 1
        print(f"{ok} {url[:50]:50s} prob={prob:.2f} pred={verdict} expected={expected}")
    print(f"\n{correct}/{len(CASES)} passed")

    print("\n--- real-world long/complex safe URLs (via app.classify + known-safe-domains) ---")
    import app as pg
    rw_correct = 0
    for url in REAL_WORLD_SAFE_CASES:
        r = pg.classify(url, deep=False)
        ok = "PASS" if r["verdict"] == "safe" else "FAIL"
        if r["verdict"] == "safe": rw_correct += 1
        print(f"{ok} {url[:60]:60s} verdict={r['verdict']} risk={r['risk_score']}")
    print(f"\n{rw_correct}/{len(REAL_WORLD_SAFE_CASES)} passed")


if __name__ == "__main__":
    main()
