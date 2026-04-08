from difflib import get_close_matches
from brand_check import BRAND_DOMAINS

FAMOUS_NAMES = [
    # Search / Portals
    "google", "bing", "yahoo", "duckduckgo", "baidu", "yandex", "zoom",

    # Social / Communication
    "facebook", "instagram", "whatsapp", "twitter", "linkedin",
    "snapchat", "telegram", "discord", "reddit", "pinterest",

    # Email / Identity
    "gmail", "outlook", "hotmail", "icloud", "proton", "zoho",

    # Video / Streaming
    "youtube", "netflix", "primevideo", "disneyplus", "hulu",
    "hbomax", "spotify", "soundcloud",

    # Ecommerce (Global + India)
    "amazon", "flipkart", "ebay", "walmart", "target", "bestbuy",
    "aliexpress", "alibaba", "etsy", "rakuten", "mercadolibre",
    "myntra", "ajio", "meesho", "snapdeal", "nykaa", "swiggy", "zomato",

    # Payments / Finance
    "paypal", "stripe", "squareup", "paytm", "phonepe", "razorpay",
    "visa", "mastercard", "americanexpress",

    # Banking
    "chase", "bankofamerica", "wellsfargo", "hsbc", "citibank",
    "sbi", "hdfc", "hdfcbank", "icicibank", "axisbank",

    # Travel / Maps
    "booking", "expedia", "airbnb", "tripadvisor", "makemytrip",
    "goibibo", "uber", "ola",

    # Tech / Software
    "microsoft", "apple", "openai", "adobe", "oracle", "ibm",
    "intel", "hp", "dell", "lenovo", "asus",

    # Developer / Cloud
    "github", "gitlab", "bitbucket", "cloudflare", "vercel",
    "netlify", "heroku", "digitalocean", "aws", "azure",

    # News / Media
    "bbc", "cnn", "nytimes", "theguardian", "reuters", "forbes", "bloomberg",

    # Education
    "wikipedia", "coursera", "udemy", "edx", "khanacademy",

    # Telecom
    "att", "verizon", "tmobile", "jio", "airtel",

    # Gaming
    "steam", "epicgames", "riotgames", "ea", "ubisoft",

    # Misc
    "quora", "stackoverflow", "medium", "tumblr", "chatgpt",

    # Indian Govt
    "uidai", "irctc", "npci", "mygov", "incometax",
]

def levenshtein(a: str, b: str) -> int:
    dp = range(len(b) + 1)
    for i, ca in enumerate(a):
        dp2 = [i + 1]
        for j, cb in enumerate(b):
            dp2.append(min(dp[j] + (ca != cb), dp[j+1] + 1, dp2[-1] + 1))
        dp = dp2
    return dp[-1]

def is_typosquat(domain: str) -> int:
    name = domain.split(".")[0].lower()
    normalized = name.translate(str.maketrans("013345", "oleeAs"))

    for brand in FAMOUS_NAMES:
        # Exact match after normalization (catches faceb00k, paypa1)
        if normalized == brand:
            # BUT: don't flag if the full domain is a legitimate known domain
            if domain in BRAND_DOMAINS:
                return 0
            return 1
        if abs(len(name) - len(brand)) <= 3:  
            if levenshtein(normalized, brand) <= 2:
                return 1

    return 0