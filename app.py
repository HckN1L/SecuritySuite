# app.py
# ---
# This is a simple backend server using Flask.
# It now uses a LOCAL function to analyze URLs, requiring NO API KEY.
# This makes the project fully self-contained for presentations.

import re
from flask import Flask, request, jsonify
from flask_cors import CORS

# Initialize the Flask app
app = Flask(__name__)
# Enable CORS to allow the HTML page to make requests to this server
CORS(app)


def analyze_url_locally(url):
    """
    Analyzes a URL based on a set of simple, local rules without needing an external API.
    Returns a dictionary with status, score, analysis, and recommendation.
    """
    score = 0
    analysis_points = []

    # --- Rule-Based Analysis ---

    # Rule 1: Check for HTTPS. Lack of HTTPS is a major red flag.
    if not url.startswith("https://"):
        score += 25
        analysis_points.append("URL is not secure (does not use HTTPS).")
    else:
        analysis_points.append("URL uses secure HTTPS.")

    # Rule 2: Check for suspicious keywords often used in phishing.
    suspicious_keywords = ["login", "secure", "account", "update", "verify", "signin", "password"]
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        score += 20
        analysis_points.append("Contains potentially suspicious keywords (e.g., 'login', 'secure').")

    # Rule 3: Check if the URL uses an IP address instead of a domain name.
    # This is a very strong indicator of a malicious site.
    domain_part = url.split('//')[1].split('/')[0]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_part):
        score += 40
        analysis_points.append("URL is an IP address, which is highly suspicious.")

    # Rule 4: Check for unusually long URLs.
    if len(url) > 75:
        score += 10
        analysis_points.append("URL is unusually long, which can be used to hide the true domain.")

    # Rule 5: Check for multiple hyphens, a common obfuscation technique.
    if domain_part.count('-') > 2:
        score += 15
        analysis_points.append("URL contains multiple hyphens, which is uncommon for legitimate sites.")

    # --- Final Verdict ---

    # Cap the score at 100
    score = min(score, 100)

    # Determine the final status and recommendation based on the score
    if score >= 65:
        status = "Malicious"
        recommendation = "This URL has several strong indicators of being malicious. Do not visit this site or enter any information."
    elif score >= 35:
        status = "Suspicious"
        recommendation = "This URL has some suspicious characteristics. Proceed with extreme caution and do not provide personal data."
    else:
        status = "Safe"
        recommendation = "This URL appears to be safe based on basic checks, but always remain vigilant."

    # Override for well-known safe domains to reduce false positives
    safe_domains = ["google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com"]
    if any(safe_domain in domain_part for safe_domain in safe_domains):
        score = 5
        status = "Safe"
        analysis_points = ["URL belongs to a well-known and trusted domain."]
        recommendation = "This URL belongs to a trusted domain and is considered safe to proceed."

    analysis_summary = " ".join(analysis_points)

    # This dictionary has the same structure the frontend expects
    return {
        "status": status,
        "score": score,
        "analysis": analysis_summary,
        "recommendation": recommendation
    }


@app.route('/scan', methods=['POST'])
def scan_url():
    """
    This function handles the /scan request from the frontend.
    It now calls the local analysis function instead of an external API.
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL not provided"}), 400
    
    url_to_scan = data['url']
    
    # Get the analysis result from our local function
    result = analyze_url_locally(url_to_scan)
    
    # The frontend expects the result inside a 'candidates' list,
    # so we will simulate that structure.
    simulated_api_response = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            # The result must be a JSON string, so we convert the dictionary to a string
                            "text": jsonify(result).get_data(as_text=True)
                        }
                    ]
                }
            }
        ]
    }
    
    return jsonify(simulated_api_response)


# This allows the script to be run directly
if __name__ == '__main__':
    # Runs the Flask server on http://127.0.0.1:5000
    app.run(port=5000, debug=True)
