import re
import os
from dotenv import load_dotenv
from urlextract import URLExtract
import requests
# --- NEW IMPORTS ---
from deep_translator import GoogleTranslator
from langdetect import detect

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
    # Keywords which help to detect spam
    # Expanded list to match the logic in main_ml.py
    keywords = [
        "urgent", "verify", "blocked", "suspended", "prize", 
        "winner", "account", "otp", "deadline", "immediate", 
        "bank", "irs", "password", "credit", "transfer"
    ]

    lowered = text.lower()

    for word in keywords:
        if word in lowered:
            signals["regex_hits"].append(word)

    if extractor.has_urls(text):
        signals["urls"] = extractor.find_urls(text)

    return signals

SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_KEY")

def check_safe_browsing(urls: list) -> str:
    if not urls:
        return "clean"

    try:
        if not SAFE_BROWSING_KEY:
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

        response = requests.post(endpoint, json=payload, timeout=4)
        # If matched it is flagged
        if response.json():
            return "flagged"

        return "clean"

    except:
        return "unknown"

# --- NEW FUNCTION FOR TRANSLATION ---
def translate_to_english(text: str) -> dict:
    """
    Detects language. If not English, translates it.
    Returns: {'original': str, 'translated': str, 'src_lang': str, 'is_translated': bool}
    """
    try:
        # Detect language (e.g., 'hi' for Hindi, 'es' for Spanish)
        lang = detect(text)
        
        if lang != 'en':
            # Translate to English for the model
            translated = GoogleTranslator(source='auto', target='en').translate(text)
            return {
                "original": text,
                "translated": translated,
                "src_lang": lang,
                "is_translated": True
            }
    except:
        # Fail silently and use original text if offline or detection fails
        pass 
        
    return {
        "original": text,
        "translated": text,
        "src_lang": "en",
        "is_translated": False
    }