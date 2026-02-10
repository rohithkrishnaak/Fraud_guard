import re
import os
from dotenv import load_dotenv
from urlextract import URLExtract
import requests
from deep_translator import GoogleTranslator
from langdetect import detect

load_dotenv()
extractor = URLExtract()
SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_KEY")

def sanitize_text(text: str) -> str:
    text = re.sub(r'[\w\.-]+@[\w\.-]+', '[EMAIL_REMOVED]', text)
    text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE_REMOVED]', text)
    return text

def extract_signals(text: str) -> dict:
    signals = {
        "regex_hits": [],
        "urls": [],
        "suspicious_tld": False
    }
    
    keywords = [
        "urgent", "immediate", "deadline", "suspended", "blocked", "expires", "act now", "alert", "attention",
        "bank", "verify", "account", "otp", "password", "pin", "cvv", "irs", "tax", "credit", "debit",
        "winner", "won", "prize", "reward", "lottery", "cash", "gift", "claim", "exclusive", "free", "whatsapp"
    ]

    lowered = text.lower()
    for word in keywords:
        if word in lowered:
            signals["regex_hits"].append(word)

    # URL Extraction
    try:
        if extractor.has_urls(text):
            found_urls = extractor.find_urls(text)
            signals["urls"] = found_urls
            
            sketchy_tlds = [".cc", ".xyz", ".top", ".info", ".club", ".work", ".gq", ".tk", ".ml"]
            for url in found_urls:
                if any(tld in url.lower() for tld in sketchy_tlds):
                    signals["suspicious_tld"] = True
    except Exception as e:
        print(f"Error extracting URLs: {e}")
        # Even if it fails, we continue so we can return the partial signals

    # RETURN MUST BE HERE (OUTSIDE try/except)
    return signals

def check_safe_browsing(urls: list) -> str:
    if not urls: return "clean"
    try:
        if not SAFE_BROWSING_KEY: return "unknown"
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
        response = requests.post(endpoint, json=payload, timeout=4)
        if response.json(): return "flagged"
        return "clean"
    except:
        return "unknown"

def translate_to_english(text: str) -> dict:
    try:
        lang = detect(text)
        if lang != 'en':
            translated = GoogleTranslator(source='auto', target='en').translate(text)
            return {"original": text, "translated": translated, "src_lang": lang, "is_translated": True}
    except:
        pass
    return {"original": text, "translated": text, "src_lang": "en", "is_translated": False}