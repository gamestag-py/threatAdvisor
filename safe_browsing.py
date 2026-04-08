import httpx
from urllib.parse import urlparse
from brand_check import is_famous_domain, BRAND_DOMAINS
from typosquatting import is_typosquat

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
]

def normalize_domain(url: str) -> str:
    """Extract and normalize domain from URL with proper www. prefix removal."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def check_google_safe_browsing(url: str, timeout: int = 6):
    api_key = "AIzaSyCUtawI7Aq0QqVZsUTpQ8eqtQTPAkunKkc"
    if not api_key:
        return {"error": "API key missing"}

    if not url.startswith(("http://", "https://")):
        return {"error": "Invalid URL format (must include http/https)"}

    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.post(
                GSB_ENDPOINT,
                params={"key": api_key},
                json=payload
            )
            return {
                "status_code": res.status_code,
                "response": res.json() if res.content else {}
            }

    except Exception as e:
        return {"error": str(e)}

def parse_gsb_result(result):
    if result.get("status_code") != 200:
        return {
            "status": "error",
            "score": 0,
            "reason": result
        }

    matches = result.get("response", {}).get("matches", [])

    VALID_THREATS = {
        "SOCIAL_ENGINEERING": 100,
        "MALWARE": 100,
        "UNWANTED_SOFTWARE": 100,
    }

    if matches:
        threat_types = list({m.get("threatType") for m in matches})

        # Calculate score (take highest severity)
        score = max([VALID_THREATS.get(t, 0) for t in threat_types])

        return {
            "status": "flagged",
            "threats": threat_types,
            "score": score,
            "is_phishing": "SOCIAL_ENGINEERING" in threat_types
        }


    return {
        "status": "clean",
        "threats": [],
        "score": 0,
        "is_phishing": False
    }



