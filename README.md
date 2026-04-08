# Phishing URL Detection System

A simple but effective machine learning-based project to detect phishing URLs. It combines basic rule checks with a trained model so that both obvious and tricky phishing links can be identified.

---

## What this project does

This system analyzes a given URL and decides whether it is **safe** or **phishing**.  
Instead of relying on just one method, it uses multiple checks together — which makes it more reliable.

---

## Key Features

- Multi-step detection (rules + ML model)
- Detects **typosquatting** (fake domains like g00gle.com)
- Identifies **brand misuse** in URLs
- Checks for **cloaking behavior**
- Handles **shortened URLs** (bit.ly, tinyurl, etc.)
- Uses a **Random Forest model** for final prediction

---

## How detection works

The system follows a step-by-step pipeline:

1. Check if URL is shortened  
2. Check if domain is a trusted brand  
3. Look for typosquatting patterns  
4. Detect brand misuse in subdomains/paths  
5. Perform cloaking check (different user-agents)  
6. Run ML model for final decision  

---

## Detection Techniques

### 1. Rule-based checks

These are quick and help catch obvious phishing:

- Known trusted domains whitelist  
- Suspicious TLDs like `.xyz`, `.top`, `.shop`, `.online`  
- Presence of symbols like `@`, `-`, etc.  
- Brand names used in strange places  
- URL shorteners  

---

### 2. Typosquatting detection

Checks if a domain looks similar to real brands using:
- Character replacement (`0 → o`, `1 → l`)
- Small spelling differences (Levenshtein distance)

---

### 3. Cloaking detection

Some phishing sites behave differently depending on who visits them.

This system:
- Sends requests using different user-agents  
- Compares responses  
- Flags suspicious differences  

---

### 4. Machine Learning model

A Random Forest classifier is used as the final decision layer.

It looks at multiple URL features like:
- URL length  
- Number of dots  
- Presence of digits  
- Domain structure  
- Suspicious keywords  
- Typosquatting score  
- Brand abuse score  

---

## Installation

### Requirements

- Python 3.8+
- pip

### Install dependencies

```bash
pip install pandas numpy scikit-learn joblib requests`
