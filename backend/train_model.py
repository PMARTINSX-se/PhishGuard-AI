"""
PhishGuard AI; Model Training Script
Trains a Random Forest classifier on a phishing URL dataset.

Usage:
    python train_model.py --dataset data/urls.csv --out models/phishing_rf.pkl

Expected CSV columns: url,label   (label: 0=safe, 1=phishing)
Datasets you can use:
  - https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
  - https://www.kaggle.com/datasets/akashkr/phishing-website-dataset
  - https://phishtank.org/developer_info.php
  - https://archive.ics.uci.edu/dataset/327/phishing+websites
A small synthetic seed dataset is auto-generated if no file is supplied.
"""
import argparse
import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, f1_score, roc_auc_score)

from feature_extractor import extract_features, to_vector, FEATURE_NAMES


def make_seed_dataset(path):
    """Generate a small labeled dataset so the project trains out of the box."""
    safe = [
        "https://www.google.com","https://github.com/openai/whisper","https://en.wikipedia.org/wiki/Phishing",
        "https://www.microsoft.com/en-us/microsoft-365","https://www.apple.com/iphone/","https://www.amazon.com/dp/B08N5WRWNW",
        "https://stackoverflow.com/questions/tagged/python","https://www.bbc.com/news","https://www.nytimes.com/section/world",
        "https://docs.python.org/3/library/json.html","https://reactjs.org/docs/getting-started.html","https://nodejs.org/en/download",
        "https://www.mozilla.org/en-US/firefox/new/","https://www.cloudflare.com/learning/","https://www.coursera.org/learn/machine-learning",
        "https://openai.com/research","https://huggingface.co/models","https://scikit-learn.org/stable/",
        "https://www.linkedin.com/in/satyanadella","https://www.netflix.com/browse","https://www.spotify.com/us/",
        "https://aws.amazon.com/ec2/","https://cloud.google.com/products","https://azure.microsoft.com/en-us/services/",
        "https://www.figma.com/files","https://www.notion.so/product","https://discord.com/channels/@me",
        "https://twitter.com/elonmusk","https://www.reddit.com/r/programming/","https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    ] * 4
    phish = [
        "http://paypa1-secure-login.tk/verify","http://amaz0n-account-update.xyz/confirm",
        "http://192.168.4.21/banking/login","https://signin-apple-id-restore.gq/auth",
        "http://login-microsft-auth.click/update-password","http://secure-paypal-billing.ml/portal",
        "http://facebook-login-recover.cf/help","http://account-verification-google.loan/signin",
        "http://wallet-update-blockchain.work/auth","http://service-suspended-netfIix.tk/restore",
        "http://confirm-amazon-order.ga/details","http://googIe-security-alert.xyz/login",
        "http://my-bank-online.click/securelogin","http://chase-bank-verification.top/login",
        "http://microsoft-365-renew.gq/auth","http://dropbox-shared-doc.tk/access",
        "http://instagram-suspended-account.cf/restore","http://linkedin-premium-offer.ml/upgrade",
        "http://outlook-mailbox-full.xyz/cleanup","http://onedrive-document.click/preview",
        "http://www.secure.bank-of-america.com.login.account.verify.tk/auth",
        "http://hsbc-uk.online-banking-secure.gq/login","http://verify-paypal-id.com.update-info.ml/portal",
        "http://barclays.co.uk.secure-login.work/auth","http://natwest-online.click/customer-area",
        "http://citibank-online.security-alert.tk/auth","http://wellsfargo-secure.account-update.xyz/login",
        "http://amazon-prime-renewal-2024.gq/billing","http://apple-icloud-locked.cf/unlock",
        "http://office365-password-expire.ml/reset","http://teams-meeting-invite.click/join",
    ] * 4
    rows = [(u, 0) for u in safe] + [(u, 1) for u in phish]
    df = pd.DataFrame(rows, columns=["url","label"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/urls.csv")
    ap.add_argument("--out", default="models/phishing_rf.pkl")
    ap.add_argument("--model", choices=["rf","lr"], default="rf")
    args = ap.parse_args()

    if not os.path.exists(args.dataset):
        print(f"[!] Dataset {args.dataset} not found - generating seed dataset.")
        df = make_seed_dataset(args.dataset)
    else:
        df = pd.read_csv(args.dataset)
    print(f"[+] Loaded {len(df)} URLs ({df['label'].sum()} phishing)")

    print("[+] Extracting features...")
    X = np.array([to_vector(extract_features(u)) for u in df["url"]])
    y = df["label"].values

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    if args.model == "rf":
        clf = RandomForestClassifier(n_estimators=200, max_depth=14, n_jobs=-1, random_state=42, class_weight="balanced")
    else:
        clf = LogisticRegression(max_iter=1000, class_weight="balanced")

    print(f"[+] Training {args.model.upper()}...")
    clf.fit(X_tr, y_tr)

    pred = clf.predict(X_te)
    proba = clf.predict_proba(X_te)[:, 1]

    print("\n=== Evaluation ===")
    print(f"Accuracy  : {accuracy_score(y_te, pred):.4f}")
    print(f"F1 Score  : {f1_score(y_te, pred):.4f}")
    try:
        print(f"ROC-AUC   : {roc_auc_score(y_te, proba):.4f}")
    except Exception:
        pass
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_te, pred))
    print("\nClassification Report:")
    print(classification_report(y_te, pred, target_names=["safe","phishing"]))

    cv = cross_val_score(clf, X, y, cv=5, scoring="f1")
    print(f"5-fold CV F1: mean={cv.mean():.4f} std={cv.std():.4f}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({"model": clf, "feature_names": FEATURE_NAMES}, args.out)
    # Plain ASCII here; Windows' console defaults to cp1252, which can't encode "✓" and would
    # otherwise crash this print *after* the model has already been saved successfully.
    print(f"\n[DONE] Saved model to {args.out}")

    if hasattr(clf, "feature_importances_"):
        print("\nTop features by importance:")
        for name, imp in sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1])[:10]:
            print(f"  {name:30s} {imp:.4f}")


if __name__ == "__main__":
    main()
