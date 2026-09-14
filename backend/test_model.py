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

def main():
    bundle = joblib.load("models/phishing_rf.pkl")
    model = bundle["model"]
    correct = 0
    for url, expected in CASES:
        vec = np.array([to_vector(extract_features(url))])
        prob = model.predict_proba(vec)[0][1]
        verdict = "phishing" if prob >= 0.5 else "safe"
        # Plain ASCII — Windows' console defaults to cp1252, which can't encode "✓"/"✗" and
        # would otherwise crash this print outright (train_model.py had the same bug).
        ok = "PASS" if verdict == expected else "FAIL"
        if verdict == expected: correct += 1
        print(f"{ok} {url[:50]:50s} prob={prob:.2f} pred={verdict} expected={expected}")
    print(f"\n{correct}/{len(CASES)} passed")

if __name__ == "__main__":
    main()
