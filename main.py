import pandas as pd
import numpy as np
import re
import os
import joblib
from urllib.parse import urlparse
from ua_check import cloaking_feature
from brand_check import is_famous_domain

# ─── Paths ───────────────────────────────────────────────────────────────
MODEL_PATH    = "model.pkl"
FEATURES_PATH = "features.npy"
LABELS_PATH   = "labels.npy"

# ─── Feature extractor ───────────────────────────────────────────────────
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    return [
        1 if url.startswith("http://") else 0,
        len(url),
        url.count("."),
        1 if "@" in url else 0,
        1 if "-" in domain else 0,
        len(domain),
        1 if re.search(r'\d', url) else 0,
        1 if domain.endswith((".xyz", ".top", ".shop", ".site", ".online", ".live")) else 0,
        1 if domain.count(".") >= 2 else 0,
        1 if is_famous_domain(domain) else 0,   # ← bug fix from earlier
    ]

# ─── Load or build features ──────────────────────────────────────────────
if os.path.exists(FEATURES_PATH) and os.path.exists(LABELS_PATH):
    print("✅ Loading cached features...")
    X = np.load(FEATURES_PATH).tolist()
    y = np.load(LABELS_PATH)
else:
    print("⏳ Building features (first run only)...")
    df = pd.read_csv("cleaned_dataset.csv")
    df = df[df['url'] != 'URL'].reset_index(drop=True)

    df_safe  = df[df['label'] == 0]
    df_phish = df[df['label'] == 1].sample(len(df_safe), random_state=42)
    df_balanced = pd.concat([df_phish, df_safe]).sample(frac=1).reset_index(drop=True)

    X = df_balanced['url'].apply(extract_features).tolist()
    y = df_balanced['label'].values

    np.save(FEATURES_PATH, X)
    np.save(LABELS_PATH,   y)
    print("✅ Features cached.")

# ─── Load or train model ─────────────────────────────────────────────────
if os.path.exists(MODEL_PATH):
    print("✅ Loading cached model...")
    model = joblib.load(MODEL_PATH)
else:
    print("⏳ Training model (first run only)...")
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    joblib.dump(model, MODEL_PATH)
    print("✅ Model cached.")

    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

# ─── Predict ─────────────────────────────────────────────────────────────
urls = [
    # ✅ Safe — Major platforms
    "https://claude.ai/",
    "https://facebook.com",
    "https://amazon.com",
    "https://chatgpt.com",
    "https://meesho.com",
    "https://youtube.com",
    "https://google.com",
    "https://instagram.com",
    "https://twitter.com",
    "https://linkedin.com",
    "https://github.com",
    "https://microsoft.com",
    "https://apple.com",
    "https://netflix.com",
    "https://spotify.com",
    "https://reddit.com",
    "https://wikipedia.org",
    "https://stackoverflow.com",
    "https://openai.com",
    "https://paypal.com",
    "https://flipkart.com",
    "https://myntra.com",
    "https://ajio.com",
    "https://nykaa.com",
    "https://zomato.com",
    "https://swiggy.com",
    "https://paytm.com",
    "https://phonepe.com",
    "https://sbi.co.in",
    "https://hdfcbank.com",
    "https://icicibank.com",
    "https://irctc.co.in",
    "https://uidai.gov.in",
    "https://incometax.gov.in",
    "https://npci.org.in",

    # ⚠️ Phishing — Typosquatting (slight misspelling of real brands)
    "https://arnazon.com",           # amazon → arnazon
    "https://faceb00k.com",          # facebook with zeros
    "https://paypa1.com",            # paypal with 1
    "https://linkedln.com",          # linkedin misspelled
    "https://micosoft.com",          # microsoft misspelled
    "https://youtobe.com",           # youtube misspelled
    "https://instagrem.com",         # instagram misspelled
    "https://flipkart.net",          # wrong TLD
    "https://paytm-wallet.com",      # fake subdomain trick
    "https://sbi-onlinebanking.com", # fake SBI

    # ⚠️ Phishing — Subdomain abuse
    "https://followfb.profilee.shop",
    "https://followx.profilee.shop/Fatimalive7265/",
    "https://amazon.login-verify.com",
    "https://secure.paypal.account-verify.xyz",
    "https://facebook.com.login-help.net",
    "https://apple.com.id-verify.shop",
    "https://google.com.signin-check.xyz",
    "https://hdfc.netbanking-secure.in",
    "https://sbi.netbanking-login.com",
    "https://irctc.booking-refund.live",

    # ⚠️ Phishing — Suspicious TLDs (.shop, .xyz, .top, .live, .site)
    "https://profilee.shop",
    "https://com.fllppkart.shop/scratch2",
    "https://sale.festiveeseason.shop/aaaaanewweb/login.php",
    "https://followfb.profilee.shop",
    "https://dhamaka-offer.live/ObKu4L/OFFER/cupboard/",
    "https://free-recharge.xyz/offer2024",
    "https://win-iphone15.top/claim-now",
    "https://lucky-draw-winner.site/redeem",
    "https://cashback-offer.live/paytm",
    "https://amazon-sale.xyz/today-deals",
    "https://flipkart-prize.shop/winner",

    # ⚠️ Phishing — Fake login/verify pages
    "https://secure-login.facebook-help.com",
    "https://accounts.google-verify.com/signin",
    "https://login.amazon-security.net/verify",
    "https://verify.paytm-kyc.com/otp",
    "https://update.sbi-account.com/login",
    "https://facebook-account-verify.com/login.php",
    "https://instagram-verify.net/account-check",
    "https://whatsapp-web-login.com/scan",
    "https://upi-cashback.com/verify-account",
    "https://aadhaar-link-bank.com/submit",

    # ⚠️ Phishing — Free gift / prize / offer scams
    "https://freegift.amazon-prize.com",
    "https://win-lucky-draw.in/amazon-prize",
    "https://jio-free-recharge.com/claim",
    "https://bsnl-free-data.xyz/offer",
    "https://paytm-cashback-offer.com/get",
    "https://phonepe-bonus.live/redeem",
    "https://free-iphone-winner.shop/form",
    "https://india-govt-scheme.xyz/apply-now",
    "https://pm-kisan-bonus.live/claim",
    "https://covid-relief-fund.site/apply",

    # ⚠️ Phishing — URL path indicators
    "https://go.redirectme.net/amazon-login",
    "http://bit.do/fake-bank-verify",
    "https://tinyurl.com/amazon-fake-offer",  # shortened URLs hiding destination
    "https://notabank.com/secure/verify/account/update/login.php",
    "https://totallylegit.com/wp-admin/includes/signin/?ref=amazon",
]

for url in urls:
    domain   = urlparse(url).netloc.lower()
    features = extract_features(url)
    prediction = model.predict([features])[0]

    if not is_famous_domain(domain):
        cloak = cloaking_feature(url)
        if cloak == 1:
            print(f"{url}: 🚨 High Confidence Phishing (Cloaking detected)")
        elif prediction == 1:
            print(f"{url}: ⚠️ Phishing (ML detected)")
        else:
            print(f"{url}: ✅ Safe")
    else:
        print(f"{url}: ✅ Safe (known brand)")