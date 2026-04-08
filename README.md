# Phishing URL Detection System

A comprehensive machine learning-based system for detecting phishing URLs using multiple detection techniques including typosquatting analysis, brand abuse detection, cloaking checks, and machine learning classification.

## Features

- **Multi-layered Detection**: Combines rule-based checks with machine learning
- **Typosquatting Detection**: Identifies URLs that mimic legitimate domains with slight misspellings or character substitutions
- **Brand Abuse Detection**: Detects when legitimate brand names appear in suspicious domains
- **Cloaking Detection**: Checks if websites behave differently based on User-Agent headers
- **Machine Learning Classification**: Uses Random Forest classifier trained on URL features
- **URL Shortener Handling**: Special handling for shortened URLs that hide their destination

## Detection Methods

### 1. Rule-Based Checks
- **Known Brand Domains**: Whitelists legitimate domains from major companies
- **Typosquatting**: Uses Levenshtein distance and character normalization (0→o, 1→l, etc.)
- **Brand in Non-Root**: Detects brand names in subdomains or paths of unknown domains
- **Suspicious TLDs**: Flags domains using .xyz, .top, .shop, .site, .online, .live
- **URL Shorteners**: Special handling for bit.ly, tinyurl.com, etc.

### 2. Cloaking Detection
- Tests URLs with different User-Agent strings (mobile, desktop, custom)
- Detects selective accessibility that indicates cloaking behavior
- Parallel HTTP requests for efficiency

### 3. Machine Learning Features
The system extracts 13 features from URLs:
1. Protocol (HTTP vs HTTPS)
2. URL length
3. Number of dots
4. Presence of @ symbol
5. Hyphen in domain
6. Domain length
7. Presence of digits
8. Phishing keywords
9. Suspicious TLD
10. Subdomain depth
11. Non-famous domain
12. Typosquatting score
13. Brand abuse score

## Installation

### Prerequisites
- Python 3.8+
- pip

### Dependencies
```bash
pip install pandas numpy scikit-learn joblib requests
```

## Usage

### Basic Usage
```python
from main import extract_features, model

# Load the trained model (happens automatically on first run)
# The model will be trained if model.pkl doesn't exist

# Test a URL
url = "https://suspicious-site.xyz/login"
features = extract_features(url)
prediction = model.predict([features])

if prediction[0] == 1:
    print("⚠️ Phishing detected")
else:
    print("✅ Safe")
```

### Running the Demo
```bash
python main.py
```

The script includes a comprehensive test suite with various URL categories:
- Safe URLs (major platforms)
- Typosquatting attacks
- Subdomain abuse
- Suspicious TLDs
- Fake login pages
- Free gift scams

## Project Structure

```
├── main.py              # Main detection script and demo
├── brand_check.py       # Brand domain whitelist and validation
├── typosquatting.py     # Typosquatting detection logic
├── ua_check.py          # User-Agent cloaking detection
├── dataset.csv          # Raw URL dataset
├── cleaned_dataset.csv  # Processed dataset
├── sample_set.csv       # Sample URLs for testing
├── features.npy         # Extracted features (cached)
├── labels.npy           # Labels for training (cached)
├── model.pkl            # Trained Random Forest model (cached)
└── README.md           # This file
```

## Data

The system uses a balanced dataset of phishing and legitimate URLs. The dataset is automatically balanced during training to ensure equal representation of both classes.

### Dataset Format
```
url,label
https://example.com,0  # 0 = safe, 1 = phishing
https://phishing.xyz,1
```

## Model Training

The Random Forest classifier is trained on the first run if `model.pkl` doesn't exist. Training includes:

- Feature extraction from URLs
- Dataset balancing
- 80/20 train/test split
- Model evaluation with accuracy and classification report

## Detection Flow

1. **URL Shortener Check**: If URL uses a shortener, mark as unverified
2. **Known Brand Check**: If domain is in whitelist, mark as safe
3. **Typosquatting Check**: Check for domain similarity to known brands
4. **Brand Abuse Check**: Check for brand names in suspicious contexts
5. **Cloaking Check**: Test User-Agent behavior
6. **ML Classification**: Final prediction using Random Forest

## Performance

The system achieves high accuracy by combining multiple detection methods:

- **Rule-based checks**: Fast, zero false positives for known patterns
- **Cloaking detection**: Identifies sophisticated phishing attempts
- **ML classification**: Catches novel phishing patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is open source. Please check the license file for details.

## Disclaimer

This tool is for educational and research purposes. Always exercise caution when visiting unknown URLs, and consider using additional security measures like antivirus software and browser extensions.</content>
<parameter name="filePath">c:\Users\Shivansh\OneDrive\Desktop\PHISHIBG\README.md