import re
import os
from dotenv import load_dotenv
from urlextract import URLExtract
import requests

load_dotenv()

def sanitize_text(text: str) -> str:
    # Hide emails
    text = re.sub(r'[\w\.-]+@[\w\.-]+', '[EMAIL_REMOVED]', text)

    # Hide phone numbers
    text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE_REMOVED]', text)

    return text



extractor = URLExtract()

def extract_signals(text: str) -> dict:
    signals = {
        "regex_hits": [],
        "urls": []
    }
#keywords which help to detect spam
    keywords = [
        "urgent",
        "verify",
        "blocked",
        "suspended",
        "prize",
        "winner",
        "account",
        "otp"
    ]

    lowered = text.lower()

    for word in keywords:
        if word in lowered:
            signals["regex_hits"].append(word)

    if extractor.has_urls(text):
        signals["urls"] = extractor.find_urls(text)

    return signals




SAFE_BROWSING_KEY =os.getenv("SAFE_BROWSING_KEY")

def check_safe_browsing(urls: list) -> str:
    if not urls:
        return "clean"

    try:
        if not SAFE_BROWSING_KEY :
            return "unknown"

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"

        payload = {
            "client": {"clientId": "fraud-guard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls]
            }
        }

        response = requests.post(endpoint, json=payload,timeout=4)
#If matched it is flagged
        if response.json():
            return "flagged"

        return "clean"

    except:
        return "unknown"


#mask sensitive info, extract suspicious keywords, check safe browser 


