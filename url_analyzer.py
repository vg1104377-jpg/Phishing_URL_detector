from urllib.parse import urlparse
import re


def analyze_url(url):
    """
    Analyze a URL using simple phishing indicators.
    This is a rule-based educational scanner.
    """

    original_url = url

    # Add scheme if the user enters something like google.com
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return {
            "status": "INVALID",
            "message": "The URL format is invalid.",
            "score": 0,
            "url": original_url
        }

    score = 0
    reasons = []

    # 1. Check HTTPS
    if parsed.scheme.lower() != "https":
        score += 2
        reasons.append("The URL does not use HTTPS.")

    # 2. Check IP address instead of domain name
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        score += 3
        reasons.append("The URL uses an IP address instead of a domain name.")

    # 3. Check for @ symbol
    if "@" in url:
        score += 3
        reasons.append("The URL contains an @ symbol.")

    # 4. Check suspicious words
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "confirm",
        "signin",
        "free",
        "gift"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        score += min(len(found_words), 3)
        reasons.append(
            "Suspicious keywords found: " + ", ".join(found_words)
        )

    # 5. Check URL length
    if len(url) > 100:
        score += 2
        reasons.append("The URL is unusually long.")

    # 6. Check excessive subdomains
    if hostname.count(".") >= 3:
        score += 2
        reasons.append("The URL contains many subdomains.")

    # 7. Check hyphen-heavy domain
    domain_name = hostname.split(".")[0]

    if domain_name.count("-") >= 2:
        score += 1
        reasons.append("The domain contains multiple hyphens.")

    # Final classification
    if score >= 6:
        status = "HIGH RISK"
        message = "This URL shows several phishing indicators."
    elif score >= 3:
        status = "SUSPICIOUS"
        message = "This URL has some suspicious characteristics."
    else:
        status = "LIKELY SAFE"
        message = "No major phishing indicators were detected."

    return {
        "status": status,
        "message": message,
        "score": score,
        "reasons": reasons,
        "url": original_url
    }