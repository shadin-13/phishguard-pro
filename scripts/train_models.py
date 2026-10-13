"""
Train and evaluate Phishing + Spam models
Saves models + prints full classification metrics
"""
import os
import sys
import csv
import re
import joblib
import numpy as np
from urllib.parse import urlparse
from collections import Counter

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

BASE = os.path.join(os.path.dirname(__file__), "..")
DATA_DIR = os.path.join(BASE, "data")
MODEL_DIR = os.path.join(BASE, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------- Feature extraction for URLs ----------
SUSPICIOUS = ["login", "signin", "bank", "account", "update", "secure", "verify",
              "password", "confirm", "paypal", "ebay", "apple", "microsoft",
              "amazon", "wallet", "crypto", "free", "bonus", "prize", "urgent",
              "suspend", "limited", "click", "unlock", "restore"]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly"]

def entropy(s):
    if not s:
        return 0.0
    from math import log2
    p = [s.count(c) / len(s) for c in set(s)]
    return -sum(x * log2(x) for x in p if x > 0)

def extract_url_features(url):
    try:
        if "://" not in url:
            url = "http://" + url
        p = urlparse(url)
        domain = p.netloc or ""
        path = p.path or ""
        query = p.query or ""
        full = url.lower()
        feats = [
            len(url),
            url.count("."),
            url.count("-"),
            url.count("_"),
            url.count("/"),
            url.count("?"),
            url.count("="),
            url.count("@"),
            url.count("&"),
            1 if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", domain) else 0,
            1 if p.scheme == "https" else 0,
            max(0, domain.count(".") - 1),
            len(path),
            len(query),
            1 if any(w in full for w in SUSPICIOUS) else 0,
            sum(c.isdigit() for c in url) / max(len(url), 1),
            sum(c.isalpha() for c in url) / max(len(url), 1),
            1 if any(s in domain for s in SHORTENERS) else 0,
            entropy(domain + path),
            len(domain),
            1 if "-" in domain else 0,
        ]
        return feats
    except Exception:
        return [0.0] * 21

def train_phishing():
    path = os.path.join(DATA_DIR, "phishing_urls.csv")
    if not os.path.exists(path):
        print("Dataset not found. Run generate_datasets.py first.")
        return
    urls, labels = [], []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            urls.append(row["url"])
            labels.append(int(row["label"]))
    print(f"Loaded {len(urls)} URLs | Label dist: {Counter(labels)}")

    X = np.array([extract_url_features(u) for u in urls])
    y = np.array(labels)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=120, max_depth=14, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    pred = clf.predict(X_test)

    print("\n===== Phishing URL Model =====")
    print("Accuracy:", round(accuracy_score(y_test, pred) * 100, 2), "%")
    print(classification_report(y_test, pred, target_names=["Legitimate", "Phishing"]))
    print("Confusion Matrix:\n", confusion_matrix(y_test, pred))

    model_path = os.path.join(MODEL_DIR, "phishing_model.joblib")
    joblib.dump({"model": clf, "feature_fn": "extract_url_features_v1"}, model_path)
    print(f"Model saved → {model_path}")
    return clf

def train_spam():
    path = os.path.join(DATA_DIR, "spam_emails.csv")
    if not os.path.exists(path):
        print("Spam dataset not found.")
        return
    texts, labels = [], []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            texts.append(row["text"])
            labels.append(int(row["label"]))
    print(f"\nLoaded {len(texts)} emails | Label dist: {Counter(labels)}")

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2))),
        ("clf", GradientBoostingClassifier(n_estimators=80, max_depth=5, random_state=42))
    ])
    pipe.fit(X_train, y_train)
    pred = pipe.predict(X_test)

    print("\n===== Spam Model =====")
    print("Accuracy:", round(accuracy_score(y_test, pred) * 100, 2), "%")
    print(classification_report(y_test, pred, target_names=["Ham", "Spam"]))
    print("Confusion Matrix:\n", confusion_matrix(y_test, pred))

    model_path = os.path.join(MODEL_DIR, "spam_model.joblib")
    joblib.dump(pipe, model_path)
    print(f"Model saved → {model_path}")
    return pipe

if __name__ == "__main__":
    print("Training PhishGuard Pro models...\n")
    train_phishing()
    train_spam()
    print("\nAll models trained and saved.")
