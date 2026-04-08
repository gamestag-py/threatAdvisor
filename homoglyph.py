import unicodedata
from brand_check import is_famous_domain
# Visually similar unicode chars mapped to their ASCII lookalike
HOMOGLYPH_MAP = {
    # Latin Extended / Latin-1
    'à':'a','á':'a','â':'a','ã':'a','ä':'a','å':'a','ā':'a','ă':'a','ą':'a',
    'è':'e','é':'e','ê':'e','ë':'e','ē':'e','ĕ':'e','ě':'e','ę':'e',
    'ì':'i','í':'i','î':'i','ï':'i','ī':'i','ĭ':'i','į':'i',
    'ò':'o','ó':'o','ô':'o','õ':'o','ö':'o','ø':'o','ō':'o','ŏ':'o','ő':'o',
    'ù':'u','ú':'u','û':'u','ü':'u','ū':'u','ŭ':'u','ů':'u','ű':'u','ų':'u',
    'ý':'y','ÿ':'y','ŷ':'y',
    'ñ':'n','ń':'n','ň':'n','ņ':'n',
    'ç':'c','ć':'c','ĉ':'c','č':'c',
    'ß':'b',  # visually close enough in some fonts
    'ð':'d','đ':'d',
    'þ':'p',
    'ğ':'g','ĝ':'g','ģ':'g',
    'ħ':'h','ĥ':'h',
    'ĵ':'j',
    'ķ':'k',
    'ĺ':'l','ļ':'l','ľ':'l','ł':'l',
    'ŕ':'r','ŗ':'r','ř':'r',
    'ś':'s','ŝ':'s','š':'s','ş':'s',
    'ţ':'t','ť':'t','ŧ':'t',
    'ŵ':'w',
    'ź':'z','ż':'z','ž':'z',

    # Cyrillic lookalikes (most dangerous for IDN attacks)
    'а':'a','е':'e','о':'o','р':'r','с':'c','х':'x','у':'y',  # Cyrillic
    'і':'i','ї':'i','ј':'j','ѕ':'s','ԁ':'d','ɡ':'g',

    # Greek lookalikes
    'α':'a','β':'b','ε':'e','ο':'o','ρ':'r','ν':'v','υ':'u',
    'κ':'k','τ':'t','χ':'x','ω':'w','η':'n','μ':'m','π':'p',

    # Mathematical / Letterlike symbols
    '𝐚':'a','𝐛':'b','𝐜':'c','𝐝':'d','𝐞':'e',
    '𝗮':'a','𝗯':'b','𝗰':'c',
    'ℯ':'e','ℰ':'e','ℴ':'o',

    # Fullwidth ASCII
    'ａ':'a','ｂ':'b','ｃ':'c','ｄ':'d','ｅ':'e','ｆ':'f','ｇ':'g',
    'ｈ':'h','ｉ':'i','ｊ':'j','ｋ':'k','ｌ':'l','ｍ':'m','ｎ':'n',
    'ｏ':'o','ｐ':'p','ｑ':'q','ｒ':'r','ｓ':'s','ｔ':'t','ｕ':'u',
    'ｖ':'v','ｗ':'w','ｘ':'x','ｙ':'y','ｚ':'z',
}

def detect_homoglyphs(url: str) -> dict:
    """
    Detects visually deceptive unicode characters in a domain name.
    
    Returns:
        {
            "suspicious": bool,
            "original": "pаypal.com",        # raw input domain
            "normalized": "paypal.com",       # ascii-mapped version
            "matches_brand": bool,            # normalized form is a known brand
            "findings": [
                {"char": "а", "position": 1, "lookalike": "a", "script": "Cyrillic"}
            ]
        }
    """
    from urllib.parse import urlparse

    if "://" not in url:
        url = "https://" + url

    host = urlparse(url).hostname or ""
    host = host.lower().rstrip(".")

    findings = []
    normalized_chars = []

    for i, ch in enumerate(host):
        if ord(ch) < 128:
            # Pure ASCII — safe
            normalized_chars.append(ch)
            continue

        ascii_eq = HOMOGLYPH_MAP.get(ch)
        if ascii_eq:
            script = unicodedata.name(ch, "").split(" ")[0]  # e.g. "CYRILLIC", "LATIN", "GREEK"
            findings.append({
                "char": ch,
                "position": i,
                "lookalike": ascii_eq,
                "script": script,
                "unicode_name": unicodedata.name(ch, "UNKNOWN"),
            })
            normalized_chars.append(ascii_eq)
        else:
            # Unicode char not in our map — still flag it
            findings.append({
                "char": ch,
                "position": i,
                "lookalike": None,
                "script": unicodedata.name(ch, "").split(" ")[0],
                "unicode_name": unicodedata.name(ch, "UNKNOWN"),
            })
            normalized_chars.append(ch)

    normalized_host = "".join(normalized_chars)
    matches_brand = is_famous_domain(normalized_host)  # your existing function

    return {
        "suspicious": len(findings) > 0,
        "original": host,
        "normalized": normalized_host,
        "matches_brand": matches_brand,
        "findings": findings,
    }