import pandas as pd
import numpy as np
import re
import os
import joblib
from urllib.parse import urlparse
from ua_check import cloaking_feature
from brand_check import is_famous_domain, BRAND_DOMAINS
from typosquatting import is_typosquat, FAMOUS_NAMES
from homoglyph import detect_homoglyphs
from safe_browsing import parse_gsb_result, check_google_safe_browsing
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# ─── Paths ────────────────────────────────────────────────────────────────
MODAL_FOLDER = "modal"

AVAILABLE_MODELS = {
    "1": {
        "name": "Cleaned Dataset Model",
        "model": os.path.join(MODAL_FOLDER, "model.pkl"),
        "features": os.path.join(MODAL_FOLDER, "features.npy"),
        "labels": os.path.join(MODAL_FOLDER, "labels.npy"),
        "dataset": "cleaned_dataset.csv",
        "url_col": "url",
        "label_col": "label",
    },
    "2": {
        "name": "PhiUSIIL Dataset Model",
        "model": os.path.join(MODAL_FOLDER, "model_phiusiil.pkl"),
        "features": os.path.join(MODAL_FOLDER, "features_phiusiil.npy"),
        "labels": os.path.join(MODAL_FOLDER, "labels_phiusiil.npy"),
        "dataset": "PhiUSIIL_Phishing_URL_Dataset.csv",
        "url_col": "URL",
        "label_col": "label",
    },
    "3": {
        "name": "3rd Dataset Model",
        "model": os.path.join(MODAL_FOLDER, "model_3.pkl"),
        "features": os.path.join(MODAL_FOLDER, "features_3.npy"),
        "labels": os.path.join(MODAL_FOLDER, "labels_3.npy"),
        "dataset": "phishing_site_urls.csv"
    }
}

SHORTENERS = {
    "bit.do", "tinyurl.com", "t.co", "goo.gl", "bit.ly",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

PHISH_WORDS = [
    "login", "verify", "account", "bank", "secure",
    "offer", "free", "win", "gift", "amazon", "flipkart",
]



def get_root_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ["ac", "co", "gov", "org"]:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def brand_in_non_root(domain: str, full_url: str = "") -> int:
    domain_clean = domain.lower().removeprefix("www.")
    root_domain = get_root_domain(domain_clean)

    # ✅ Allow legit domains + subdomains
    if root_domain in BRAND_DOMAINS:
        return 0

    hostname = domain_clean
    root_name = root_domain.split(".")[0]

    for brand in FAMOUS_NAMES:

        # 🚫 skip very small brands (prevents noise)
        if len(brand) <= 3:
            continue

        # ✅ Brand inside subdomain (e.g. paypal.secure-login.com)
        if re.search(rf"\b{brand}\b", hostname) and brand not in root_name:
            return 1

        # ✅ Brand used as prefix/suffix in root (e.g. amazon-login.com)
        if re.match(rf"^{brand}[-\.]", root_name) or re.match(rf".*[-\.]{brand}$", root_name):
            return 1

    # ✅ Check URL path/query
    if full_url:
        parsed = urlparse(full_url)
        path_query = (parsed.path + " " + parsed.query).lower()

        for brand in FAMOUS_NAMES:
            if len(brand) <= 3:
                continue

            if re.search(rf"\b{brand}\b", path_query):
                return 1

    return 0


def extract_features(url: str) -> list:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().removeprefix("www.")
    return [
        1 if url.startswith("http://") else 0,
        # len(domain),
        # url.count("."),
        1 if "@" in url else 0,
        1 if "-" in domain else 0,
        len(domain),
        1 if re.search(r"\d", url) else 0,
        1 if any(re.search(rf"\b{w}\b", url.lower()) for w in PHISH_WORDS) else 0,
        1 if domain.endswith((".xyz", ".top", ".shop", ".site", ".online", ".live")) else 0,
        1 if domain.count(".") >= 3 else 0,
        0 if is_famous_domain(domain) else 1,
        is_typosquat(domain),
        brand_in_non_root(domain),
        1 if detect_homoglyphs(domain)["suspicious"] else 0,
    ]


# ─── Model Loading / Training ─────────────────────────────────────────────
def _build_features(info: dict) -> tuple:
    """Build and cache feature matrix for a given model config."""
    feat_path, label_path = info["features"], info["labels"]

    if os.path.exists(feat_path) and os.path.exists(label_path):
        print(f"  ✅ Loading cached features for {info['name']}...")
        return np.load(feat_path).tolist(), np.load(label_path)

    print(f"  ⏳ Building features for {info['name']} (first run)...")
    df = pd.read_csv(info["dataset"])
    url_col, label_col = info["url_col"], info["label_col"]

    if "PhiUSIIL" in info["dataset"]:
        df = df.dropna(subset=[url_col, label_col]).reset_index(drop=True)
    else:
        df = df[df[url_col] != "URL"].reset_index(drop=True)

    df_safe  = df[df[label_col] == 0]
    df_phish = df[df[label_col] == 1].sample(len(df_safe), random_state=42)
    df_bal   = pd.concat([df_phish, df_safe]).sample(frac=1).reset_index(drop=True)

    print(f"  Safe: {len(df_safe)}, Phishing: {len(df_phish)}")
    X = df_bal[url_col].apply(extract_features).tolist()
    y = df_bal[label_col].values

    np.save(feat_path, X)
    np.save(label_path, y)
    print(f"  ✅ Features cached for {info['name']}.")
    return X, y


def _load_or_train(info: dict):
    """Return a trained sklearn model, loading from disk or training fresh."""
    X, y = _build_features(info)

    if os.path.exists(info["model"]):
        print(f"  ✅ Loading cached model: {info['name']}...")
        return joblib.load(info["model"])

    print(f"  ⏳ Training {info['name']} (first run)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    joblib.dump(clf, info["model"])

    y_pred = clf.predict(X_test)
    print(f"  Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred))
    return clf


def load_all_models() -> dict:
    """Load (or train) every model and return {key: sklearn_model}."""
    print("\n" + "=" * 60)
    print("🔄 Loading all models...")
    print("=" * 60)
    models = {}
    for key, info in AVAILABLE_MODELS.items():
        print(f"\n[Model {key}] {info['name']}")
        models[key] = _load_or_train(info)
    print("\n✅ All models ready.\n" + "=" * 60)
    return models


# ─── Core Prediction Function ─────────────────────────────────────────────
def predict_url(url: str, model) -> dict:
    """
    Analyse a single URL and return a structured result dict.

    Parameters
    ----------
    url   : The URL string to analyse.
    model : A fitted sklearn model (e.g. from load_all_models()["1"]).

    Returns
    -------
    {
        "url":        str,
        "label":      "safe" | "phishing" | "unverified",
        "confidence": "high" | "medium" | "low",
        "reason":     str,
        "emoji":      str,
    }
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower().removeprefix("www.")

    # 1. URL shortener — destination unknown
    if domain in SHORTENERS:
        return {
            "url": url, "label": "unverified",
            "confidence": "low",
            "reason": "URL shortener — destination unknown",
            "emoji": "⚠️",
        }

    # 2. Known/famous domain — immediate safe exit
    if is_famous_domain(domain):
        return {
            "url": url, "label": "safe",
            "confidence": "high",
            "reason": "Known brand domain",
            "emoji": "✅",
        }

    # 3. Typosquat check
    if is_typosquat(domain):
        return {
            "url": url, "label": "phishing",
            "confidence": "high",
            "reason": "Typosquat detected",
            "emoji": "⚠️",
        }

    # 4. Brand abuse (+ optional cloaking escalation)
    if brand_in_non_root(domain, url):
        cloak = cloaking_feature(url)
        if cloak == 1:
            return {
                "url": url, "label": "phishing",
                "confidence": "high",
                "reason": "Brand abuse + cloaking detected",
                "emoji": "🚨",
            }
        return {
            "url": url, "label": "phishing",
            "confidence": "medium",
            "reason": "Brand abuse detected",
            "emoji": "⚠️",
        }

    # 5. Google Safe Browsing
    gsb = parse_gsb_result(check_google_safe_browsing(url))
    if gsb["score"] > 0:
        return {
            "url": url, "label": "phishing",
            "confidence": "high",
            "reason": f"Flagged by Google Safe Browsing: {gsb['threats']}",
            "emoji": "🚨",
        }

    # 6. Cloaking standalone
    if cloaking_feature(url) == 1:
        return {
            "url": url, "label": "phishing",
            "confidence": "medium",
            "reason": "Cloaking detected",
            "emoji": "🚨",
        }

    # 7. ML model fallback
    features   = extract_features(url)
    print(features)
    prediction = model.predict([features])[0]
    print(model.predict([features]))
    if prediction == 1:
        return {
            "url": url, "label": "phishing",
            "confidence": "low",
            "reason": "ML model flagged as phishing",
            "emoji": "⚠️",
        }

    return {
        "url": url, "label": "safe",
        "confidence": "medium",
        "reason": "Passed all checks",
        "emoji": "✅",
    }


