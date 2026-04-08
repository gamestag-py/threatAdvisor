from urllib.parse import urlparse
import re
BRAND_DOMAINS = {
    # Search
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    # Social
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "linkedin.com", "snapchat.com", "telegram.org", "discord.com", "reddit.com", "pinterest.com",
    # Email
    "gmail.com", "outlook.com", "hotmail.com", "icloud.com", "proton.me", "zoho.com",
    # Video / Streaming
    "youtube.com", "netflix.com", "primevideo.com", "disneyplus.com",
    "hulu.com", "hbomax.com", "spotify.com", "soundcloud.com",
    # Ecommerce
    "amazon.com", "amazon.in", "flipkart.com", "ebay.com", "walmart.com",
    "target.com", "bestbuy.com", "aliexpress.com", "alibaba.com",
    "etsy.com", "rakuten.co.jp", "mercadolibre.com",
    "myntra.com", "ajio.com", "meesho.com", "snapdeal.com", "nykaa.com",
    "swiggy.com", "zomato.com",
    # Payments
    "paypal.com", "stripe.com", "squareup.com", "paytm.com", "phonepe.com",
    "razorpay.com", "visa.com", "mastercard.com", "americanexpress.com",
    # Banking
    "chase.com", "bankofamerica.com", "wellsfargo.com", "hsbc.com", "citibank.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    # Travel
    "booking.com", "expedia.com", "airbnb.com", "tripadvisor.com",
    "makemytrip.com", "goibibo.com", "uber.com", "ola.com",
    # Tech
    "microsoft.com", "apple.com", "openai.com", "adobe.com", "oracle.com",
    "ibm.com", "intel.com", "hp.com", "dell.com", "lenovo.com", "asus.com",
    # Developer / Cloud
    "github.com", "gitlab.com", "bitbucket.org", "cloudflare.com",
    "vercel.com", "netlify.com", "heroku.com", "digitalocean.com",
    "aws.amazon.com", "cloud.google.com", "azure.microsoft.com",
    # News
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com",
    "reuters.com", "forbes.com", "bloomberg.com",
    # Education
    "wikipedia.org", "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    # Telecom
    "att.com", "verizon.com", "tmobile.com", "jio.com", "airtel.in", "vi.in",
    # Gaming
    "steampowered.com", "epicgames.com", "riotgames.com", "ea.com", "ubisoft.com",
    # Misc
    "quora.com", "stackoverflow.com", "medium.com", "tumblr.com",
    "chatgpt.com", "claude.ai",
    # Indian Govt
    "uidai.gov.in", "irctc.co.in", "npci.org.in", "mygov.in",
    "incometax.gov.in", "india.gov.in",
}

COMMON_TLDS = [".com", ".in", ".net", ".org", ".co", ".io"]

def expand_domains(domains):
    expanded = set(domains)
    for d in domains:
        name = d.split(".")[0]
        for tld in COMMON_TLDS:
            expanded.add(name + tld)
    return list(expanded)

ALL_DOMAINS = expand_domains(BRAND_DOMAINS)




BRAND_DOMAINS_SET = set(ALL_DOMAINS)  # O(1) lookups



# Also auto-whitelist any *.gov.in / *.gov.* domain
def is_famous_domain(domain: str) -> bool:
    domain = domain.lower().lstrip("www.")
    if domain in BRAND_DOMAINS:
        return True
    # Auto-trust all government domains
    if re.search(r'\.gov\.[a-z]{2,}$', domain) or domain.endswith('.gov'):
        return True
    return False

