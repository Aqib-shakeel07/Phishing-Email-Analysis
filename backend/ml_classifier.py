import os
import re
import joblib
import numpy as np
import pandas as pd
from helpers import (
    extract_domain, get_full_host, load_brands,
    similarity, clamp
)
from config import MODEL_PATH, DATASET_PATH
from logger import logger


FEATURE_NAMES = [
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "reply_to_mismatch",
    "return_path_mismatch",
    "display_name_spoof",
    "lookalike_domain",
    "url_count",
    "ip_url_count",
    "shortener_count",
    "suspicious_tld_count",
    "punycode_count",
    "at_symbol_count",
    "long_url_count",
    "urgency_hits",
    "threat_hits",
    "credential_hits",
    "reward_hits",
    "attachment_count",
    "dangerous_attachment_count",
    "html_only",
    "has_form",
    "shouty",
]


class MLClassifier:
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self._load()

    # ---------------- Public ----------------

    def is_ready(self) -> bool:
        return self.model is not None

    def predict(self, header: dict, url: dict,
                content: dict, attachment: dict) -> float:
        """Return 0-100 phishing probability. 0 if model unavailable."""
        if not self.is_ready():
            return 0.0
        try:
            features = self.extract_features(header, url, content, attachment)
            X = pd.DataFrame([features], columns=FEATURE_NAMES)
            proba = self.model.predict_proba(X)[0][1]
            return clamp(proba * 100, 0, 100)
        except Exception as e:
            logger.warning(f"ML predict failed: {e}")
            return 0.0

    def extract_features(self, header: dict, url: dict,
                         content: dict, attachment: dict) -> dict:
        urls = url.get("urls", []) or []
        atts = attachment.get("attachments", []) or []

        keyword_hits = content.get("matched_keywords", {}) or {}

        return {
            "spf_fail": int(header.get("spf_pass") is False),
            "dkim_fail": int(header.get("dkim_pass") is False),
            "dmarc_fail": int(header.get("dmarc_pass") is False),
            "reply_to_mismatch": int(
                header.get("reply_to_domain") is not None
                and header.get("reply_to_domain") != header.get("sender_domain")
            ),
            "return_path_mismatch": int(
                header.get("return_path_domain") is not None
                and header.get("return_path_domain") != header.get("sender_domain")
            ),
            "display_name_spoof": int(any(
                "Display name impersonates" in f
                for f in header.get("flags", [])
            )),
            "lookalike_domain": int(any(
                "resembles brand" in f.lower()
                for f in url.get("flags", [])
            )),
            "url_count": len(urls),
            "ip_url_count": sum(1 for u in urls if u.get("flags") and
                                any("IP-based" in f for f in u["flags"])),
            "shortener_count": sum(1 for u in urls if u.get("flags") and
                                   any("shortener" in f.lower() for f in u["flags"])),
            "suspicious_tld_count": sum(1 for u in urls if u.get("flags") and
                                        any("TLD" in f for f in u["flags"])),
            "punycode_count": sum(1 for u in urls if u.get("flags") and
                                  any("Punycode" in f for f in u["flags"])),
            "at_symbol_count": sum(1 for u in urls if u.get("flags") and
                                   any("@" in f for f in u["flags"])),
            "long_url_count": sum(1 for u in urls if u.get("flags") and
                                  any("long URL" in f for f in u["flags"])),
            "urgency_hits": len(keyword_hits.get("urgency", [])),
            "threat_hits": len(keyword_hits.get("threat", [])),
            "credential_hits": len(keyword_hits.get("credential_request", [])),
            "reward_hits": len(keyword_hits.get("reward", [])),
            "attachment_count": len(atts),
            "dangerous_attachment_count": sum(
                1 for a in atts
                if any("Dangerous" in f or "Double extension" in f
                       for f in a.get("flags", []))
            ),
            "html_only": int(content.get("has_html") and not content.get("has_plain")),
            "has_form": int(any("form" in f.lower() for f in content.get("flags", []))),
            "shouty": int(any("uppercase" in f.lower() or "punctuation" in f.lower()
                              for f in content.get("flags", []))),
        }

    # ---------------- Training ----------------

    def train(self, dataset_path: str = DATASET_PATH,
              model_out: str = MODEL_PATH) -> dict:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, classification_report

        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")

        df = pd.read_csv(dataset_path)
        if "label" not in df.columns:
            raise ValueError("Dataset must have a 'label' column (0=legit, 1=phishing)")

        missing = [c for c in FEATURE_NAMES if c not in df.columns]
        if missing:
            raise ValueError(f"Dataset missing columns: {missing}")

        X = df[FEATURE_NAMES]
        y = df["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_train, y_train)

        preds = clf.predict(X_test)
        acc = accuracy_score(y_test, preds)
        report = classification_report(y_test, preds, output_dict=True)

        os.makedirs(os.path.dirname(model_out), exist_ok=True)
        joblib.dump(clf, model_out)
        self.model = clf

        logger.info(f"Model trained. Accuracy={acc:.4f}")
        return {
            "accuracy": acc,
            "report": report,
            "model_path": model_out,
        }

    # ---------------- Internal ----------------

    def _load(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Loaded ML model: {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")
                self.model = None
        else:
            logger.info("No ML model found — ML scoring disabled")


def generate_synthetic_dataset(out_path: str = DATASET_PATH, n: int = 2000):
    """Quick bootstrap dataset generator for demo/testing."""
    import random
    random.seed(42)
    rows = []
    for _ in range(n):
        label = random.randint(0, 1)
        if label == 1:
            row = {
                "spf_fail": random.choice([0, 1, 1]),
                "dkim_fail": random.choice([0, 1, 1]),
                "dmarc_fail": random.choice([0, 1, 1]),
                "reply_to_mismatch": random.choice([0, 1]),
                "return_path_mismatch": random.choice([0, 1]),
                "display_name_spoof": random.choice([0, 1]),
                "lookalike_domain": random.choice([0, 1, 1]),
                "url_count": random.randint(1, 12),
                "ip_url_count": random.randint(0, 3),
                "shortener_count": random.randint(0, 3),
                "suspicious_tld_count": random.randint(0, 3),
                "punycode_count": random.randint(0, 2),
                "at_symbol_count": random.randint(0, 2),
                "long_url_count": random.randint(0, 3),
                "urgency_hits": random.randint(0, 5),
                "threat_hits": random.randint(0, 4),
                "credential_hits": random.randint(0, 5),
                "reward_hits": random.randint(0, 3),
                "attachment_count": random.randint(0, 3),
                "dangerous_attachment_count": random.randint(0, 2),
                "html_only": random.choice([0, 1]),
                "has_form": random.choice([0, 1]),
                "shouty": random.choice([0, 1]),
                "label": 1,
            }
        else:
            row = {
                "spf_fail": 0,
                "dkim_fail": 0,
                "dmarc_fail": 0,
                "reply_to_mismatch": 0,
                "return_path_mismatch": 0,
                "display_name_spoof": 0,
                "lookalike_domain": 0,
                "url_count": random.randint(0, 4),
                "ip_url_count": 0,
                "shortener_count": 0,
                "suspicious_tld_count": 0,
                "punycode_count": 0,
                "at_symbol_count": 0,
                "long_url_count": 0,
                "urgency_hits": random.randint(0, 1),
                "threat_hits": 0,
                "credential_hits": 0,
                "reward_hits": 0,
                "attachment_count": random.randint(0, 2),
                "dangerous_attachment_count": 0,
                "html_only": random.choice([0, 1]),
                "has_form": 0,
                "shouty": 0,
                "label": 0,
            }
        rows.append(row)

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    df.to_csv(out_path, index=False)
    logger.info(f"Synthetic dataset written: {out_path} ({len(df)} rows)")
    return out_path