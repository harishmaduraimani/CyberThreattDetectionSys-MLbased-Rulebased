import os
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
import whois
from engine.detection_result import DetectionResult
from ml.url_ml_detector import predict_ml_url_risk

SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account", "bank", "password"]
def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "https://" + url
    return url
def uses_ip_address(hostname):
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False
def get_domain_age_days(hostname):
    if not hostname or uses_ip_address(hostname):
        return None

    try:
        # Ask WHOIS database for domain registration details
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        # Calculate domain age in days
        age = datetime.now(timezone.utc) - creation_date
        return age.days

    except Exception:
        return None
def analyze_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5, stream=True)

        # Count how many redirects happened
        redirect_count = len(response.history)
        final_url = response.url

        # Close the connection cleanly
        response.close()
        return redirect_count, final_url

    except requests.RequestException:
        return None, None
def extract_url_features(url):
    parsed_url = urlparse(url)

    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname or ""
    lower_url = url.lower()

    suspicious_word_count = 0

    for word in SUSPICIOUS_WORDS:
        if word in lower_url:
            suspicious_word_count += 1

    return {
        "url_length": len(url),
        "uses_http": 1 if scheme == "http" else 0,
        "uses_https": 1 if scheme == "https" else 0,
        "uses_ip": 1 if uses_ip_address(hostname) else 0,
        "suspicious_word_count": suspicious_word_count,
        "has_at_symbol": 1 if "@" in url else 0,
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "path_length": len(parsed_url.path)
    }
def detect_url(url):
    url = normalize_url(url)
    risk_score = 0
    reasons = []
    # Parse URL into scheme, hostname, path, etc.
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname
    domain = hostname.lower() if hostname else ""
    if scheme == "http":
        risk_score += 20
        reasons.append("URL uses HTTP instead of HTTPS")
    if uses_ip_address(domain):
        risk_score += 30
        reasons.append("URL uses an IP address instead of a domain name")
    if len(url) > 75:
        risk_score += 15
        reasons.append("URL is unusually long")
    for word in SUSPICIOUS_WORDS:
        if word in url.lower():
            risk_score += 10
            reasons.append(f"URL contains suspicious word: {word}")
    if "@" in url:
        risk_score += 25
        reasons.append("URL contains @ symbol")
    if domain.count(".") >= 4:
        risk_score += 15
        reasons.append("Domain contains many dots")

    if domain.count("-") >= 2:
        risk_score += 10
        reasons.append("Domain contains many hyphens")
    domain_age_days = get_domain_age_days(domain)
    print(f"Domain age (days): {domain_age_days}")  # Debugging output
    if domain_age_days is not None and domain_age_days < 30:
        risk_score += 25
        reasons.append(f"Domain is very new: {domain_age_days} days old")
    redirect_count, final_url = analyze_redirects(url)
    print(f"Redirect count: {redirect_count}, Final URL: {final_url}")  # Debugging output

    if redirect_count is not None and redirect_count >= 3:
        risk_score += 20
        reasons.append(f"URL redirects many times: {redirect_count} redirects")

    if final_url is not None:
        final_domain = urlparse(final_url).hostname

        if final_domain and domain and final_domain.lower() != domain:
            risk_score += 15
            reasons.append(f"URL redirects to a different domain: {final_domain}")
    if risk_score > 100:
        risk_score = 100

    # Decide verdict
    if risk_score >= 70:
        verdict = "Dangerous"
    elif risk_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
    if not reasons:
        reasons.append("No suspicious URL indicators found")
    
    
    features = extract_url_features(url)

    rule_based_score = risk_score
    # Send same features to ML
    ml_risk_score, ml_reason = predict_ml_url_risk(features)
    if ml_risk_score is None:
        risk_score = rule_based_score
    else:
        risk_score =max(rule_based_score, ml_risk_score)
    reasons.append(f"Rule-based URL risk score: {rule_based_score}")
    reasons.append(ml_reason)
    reasons.append(f"Combined URL risk score: {risk_score}")
    # Return structured result
    return DetectionResult(
        detectorname="URL Phishing Detector",
        riskscore=risk_score,
        perdict=verdict,
        reason="; ".join(reasons),
        parameters={
        "url_length": features["url_length"],
        "uses_http": features["uses_http"],
        "uses_https": features["uses_https"],
        "uses_ip": features["uses_ip"],
        "suspicious_word_count": features["suspicious_word_count"],
        "has_at_symbol": features["has_at_symbol"],
        "dot_count": features["dot_count"],
        "hyphen_count": features["hyphen_count"],
        "path_length": features["path_length"],
        "domain_age_days": domain_age_days,
        "redirect_count": redirect_count,
        "final_url": final_url,
        "rule_based_score": rule_based_score,
        "ml_risk_score": ml_risk_score,
        "final_score": risk_score
    }
    )

