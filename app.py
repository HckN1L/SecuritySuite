import re
import socket
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


def analyze_url_locally(url):
    """
    Analyzes a URL using a professional-grade, local rule-based engine.
    This includes real-time checks for domain existence and website liveness.
    """
    score = 0
    analysis_points = []

    try:
        if not re.match(r'^(?:http|ftp)s?://', url):
            url = 'https://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain or '.' not in domain and domain.lower() != 'localhost':
            raise ValueError("The domain structure is invalid.")
        path = parsed_url.path
    except ValueError as e:
        return {
            "status": "Invalid URL", "score": 100,
            "analysis_points": [f"URL format is invalid: {e}"],
            "recommendation": "Please enter a valid URL (e.g., example.com)."
        }

    try:
        ip_address = socket.gethostbyname(domain)
        analysis_points.append(f"OK: Domain '{domain}' resolves to IP {ip_address}.")
        
        try:
            response = requests.head(url, timeout=3, allow_redirects=True)
            if response.status_code < 400:
                analysis_points.append(f"OK: Website is live and responding (Status: {response.status_code}).")
            else:
                score += 10
                analysis_points.append(f"Warning: Website returned an error status (Code: {response.status_code}).")
        except requests.exceptions.RequestException:
            score += 25
            analysis_points.append("High Risk: Domain exists but the website is not responding or unreachable.")

    except socket.gaierror:
        return {
            "status": "Domain Not Found", "score": 100,
            "analysis_points": ["Critical Risk: This domain does not appear to exist."],
            "recommendation": "The domain is not registered. This could be a typo or the site is offline. Do not proceed."
        }

    if parsed_url.scheme != "https":
        score += 25
        analysis_points.append("High Risk: Connection is not secure (lacks HTTPS).")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score += 40
        analysis_points.append("Critical Risk: Website uses a direct IP address, a common tactic for malicious sites.")

    shorteners = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com']
    if any(shortener in domain for shortener in shorteners):
        score += 25
        analysis_points.append("High Risk: URL uses a link shortener, which hides the final destination.")

    keywords = ["login", "secure", "account", "update", "verify", "signin", "password", "banking", "confirm", "support"]
    if any(keyword in (domain + path).lower() for keyword in keywords):
        score += 15
        analysis_points.append("Warning: URL contains potentially suspicious keywords.")

    brands = ["google", "paypal", "facebook", "amazon", "microsoft", "apple", "netflix"]
    domain_parts = domain.lower().split('.')
    for brand in brands:
        if brand in domain_parts and brand != domain_parts[-2]:
            score += 30
            analysis_points.append(f"Critical Risk: Potential brand impersonation of '{brand.title()}'.")
            break

    if domain.count('.') > 3:
        score += 15
        analysis_points.append("Warning: URL has an excessive number of subdomains.")

    suspicious_tlds = ['.xyz', '.top', '.link', '.click', '.buzz', '.live', '.fit', '.gq', '.work', '.loan']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 20
        analysis_points.append(f"High Risk: The Top-Level Domain is often associated with malicious sites.")

    malicious_ext = ['.exe', '.zip', '.rar', '.js', '.vbs', '.scr', '.msi']
    if any(path.lower().endswith(ext) for ext in malicious_ext):
        score += 35
        analysis_points.append("Critical Risk: URL path points directly to a potentially malicious file download.")

    score = min(score, 100)
    
    if score >= 70:
        status = "Malicious"
        recommendation = "This URL has several critical indicators of being malicious. Do not visit this site or enter any information."
    elif score >= 40:
        status = "Suspicious"
        recommendation = "This URL has multiple suspicious characteristics. Proceed with extreme caution."
    elif score >= 20:
        status = "Potentially Unsafe"
        recommendation = "This URL has some low-risk warnings. Be vigilant and do not provide sensitive data."
    else:
        status = "Likely Safe"
        recommendation = "This URL appears to be safe based on our checks, but always exercise caution."

    safe_domains = ["google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com", "github.com", "x.com"]
    if any(domain.endswith(safe) for safe in safe_domains) and score < 70:
        score = 5
        status = "Safe"
        analysis_points = [f"OK: URL belongs to the trusted domain '{domain}'."]
        recommendation = "This URL belongs to a trusted domain and is considered safe to proceed."

    return {
        "status": status,
        "score": score,
        "analysis_points": analysis_points,
        "recommendation": recommendation
    }


@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL not provided"}), 400
    url_to_scan = data['url']
    result = analyze_url_locally(url_to_scan)
    simulated_api_response = {
        "candidates": [{"content": {"parts": [{"text": jsonify(result).get_data(as_text=True)}]}}]
    }
    return jsonify(simulated_api_response)


if __name__ == '__main__':
    app.run(port=5000, debug=True)
