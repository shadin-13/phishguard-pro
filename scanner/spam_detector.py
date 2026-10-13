"""
Spam Detector - Loads trained TF-IDF + GradientBoosting model (7k samples)
"""
import os
import re
import joblib

class SpamDetector:
    def __init__(self, model_path=None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), "..", "models", "spam_model.joblib")
        self.model = None
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            print(f"[SpamDetector] Loaded model from {model_path}")
        else:
            print("[SpamDetector] WARNING: No trained model found.")

    def _clean(self, text):
        text = text.lower()
        text = re.sub(r"http\S+", " URL ", text)
        text = re.sub(r"[^a-zA-Z\s]", " ", text)
        return re.sub(r"\s+", " ", text).strip()

    def predict(self, text: str) -> dict:
        if not text or len(text.strip()) < 5:
            return {"is_spam": False, "confidence": 0.0, "label": "Insufficient text",
                    "risk_score": 0, "threat_level": "None"}

        if self.model is None:
            return {"is_spam": False, "confidence": 0.0, "label": "Model not loaded",
                    "risk_score": 0, "threat_level": "None"}

        cleaned = self._clean(text)
        proba = self.model.predict_proba([cleaned])[0]
        spam_prob = float(proba[1])
        is_spam = spam_prob >= 0.5
        risk = int(spam_prob * 100)
        if risk >= 80:
            level = "Critical"
        elif risk >= 60:
            level = "High"
        elif risk >= 40:
            level = "Medium"
        else:
            level = "Low"

        return {
            "is_spam": bool(is_spam),
            "confidence": round(spam_prob * 100, 2),
            "label": "Spam / Threat" if is_spam else "Clean / Ham",
            "risk_score": risk,
            "threat_level": level
        }
