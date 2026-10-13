"""
AI URL Threat Detector - Loads trained RandomForest model (12k samples)
"""
import re
import os
import joblib
import numpy as np
from urllib.parse import urlparse

SUSPICIOUS = ["login", "signin", "bank", "account", "update", "secure", "verify",
              "password", "confirm", "paypal", "ebay", "apple", "microsoft",
              "amazon", "wallet", "crypto", "free", "bonus", "prize", "urgent",
              "suspend", "limited", "click", "unlock", "restore"]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly"]

def _entropy(s):
    if not s:
        return 0.0
    from math import log2
    p = [s.count(c) / len(s) for c in set(s)]
    return -sum(x * log2(x) for x in p if x > 0)

def extract_features(url):
    try:
        if "://" not in url:
            url = "http://" + url
        p = urlparse(url)
        domain = p.netloc or ""
        path = p.path or ""
        query = p.query or ""
        full = url.lower()
        return [
            len(url), url.count("."), url.count("-"), url.count("_"),
            url.count("/"), url.count("?"), url.count("="), url.count("@"),
            url.count("&"),
            1 if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", domain) else 0,
            1 if p.scheme == "https" else 0,
            max(0, domain.count(".") - 1),
            len(path), len(query),
            1 if any(w in full for w in SUSPICIOUS) else 0,
            sum(c.isdigit() for c in url) / max(len(url), 1),
            sum(c.isalpha() for c in url) / max(len(url), 1),
            1 if any(s in domain for s in SHORTENERS) else 0,
            _entropy(domain + path),
            len(domain),
            1 if "-" in domain else 0,
        ]
    except Exception:
        return [0.0] * 21

class PhishingDetector:
    def __init__(self, model_path=None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.joblib")
        self.model = None
        if os.path.exists(model_path):
            data = joblib.load(model_path)
            self.model = data["model"] if isinstance(data, dict) else data
            print(f"[PhishingDetector] Loaded model from {model_path}")
        else:
            print("[PhishingDetector] WARNING: No trained model found. Using rule-based fallback.")

    def predict(self, url: str) -> dict:
        if not url or not isinstance(url, str):
            return {"is_phishing": False, "confidence": 0.0, "label": "Invalid URL",
                    "risk_score": 0, "threat_level": "None", "url": url}

        feats = np.array(extract_features(url)).reshape(1, -1)
        if self.model is not None:
            proba = self.model.predict_proba(feats)[0]
            phishing_prob = float(proba[1]) if len(proba) > 1 else 0.0
        else:
            # Rule fallback
            phishing_prob = 0.3
            parsed = urlparse(url if "://" in url else "http://" + url)
            if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", parsed.netloc or ""):
                phishing_prob += 0.35
            if any(s in (parsed.netloc or "") for s in SHORTENERS):
                phishing_prob += 0.2
            if any(w in url.lower() for w in SUSPICIOUS):
                phishing_prob += 0.2
            phishing_prob = min(phishing_prob, 0.95)

        is_phishing = phishing_prob >= 0.50
        risk = int(phishing_prob * 100)
        if risk >= 80:
            level = "Critical"
        elif risk >= 60:
            level = "High"
        elif risk >= 40:
            level = "Medium"
        else:
            level = "Low"

        return {
            "is_phishing": bool(is_phishing),
            "confidence": round(phishing_prob * 100, 2),
            "label": "Malicious / Phishing" if is_phishing else "Likely Safe",
            "risk_score": risk,
            "threat_level": level,
            "url": url
        }
