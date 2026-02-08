import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

# 1. Load Environment Variables
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    # Fail loudly if key is missing so we know immediately
    print("⚠️ WARNING: GEMINI_API_KEY not found in .env file.")

# 2. Configure Gemini
# Using 'gemini-1.5-flash' for speed, or 'gemini-pro' for reasoning
try:
    genai.configure(api_key=api_key)
    # trialing 'gemini-flash-latest' which is optimized for content generation
    model = genai.GenerativeModel('gemini-flash-latest')
except Exception as e:
    print(f"Error configuring Gemini: {e}")

def analyze_with_ai(sanitized_text: str, static_signals: dict = None) -> dict:
    """
    Analyzes text using Gemini and forces a strict JSON response.
    """
    if static_signals is None:
        static_signals = {}

    # 3. The Strict Prompt
    # We explicitly tell the AI the JSON structure we need.
    prompt = f"""
    Act as a world-class cybersecurity expert. Analyze the following suspicious text for fraud/phishing.
    
    TEXT TO ANALYZE:
    "{sanitized_text}"

    CONTEXT (Static Analysis Results):
    - Keywords Found: {static_signals.get('regex_hits', [])}
    - Links Found: {static_signals.get('urls', [])}

    TASK:
    Return a valid JSON object. Do NOT include markdown formatting (like ```json). 
    
    REQUIRED JSON STRUCTURE:
    {{
        "risk_score": <int 0-100>,
        "verdict": "<SAFE | SUSPICIOUS | HIGH_RISK>",
        "verdict_color": "<#00C851 for Safe | #FFA500 for Suspicious | #FF4B4B for High Risk>",
        "confidence": <float 0.0-1.0>,
        "analysis": {{
            "psychological_triggers": [
                {{ "type": "<Short Label>", "description": "<One sentence explanation>" }}
            ],
            "technical_flags": [
                {{ "type": "<Short Label>", "description": "<Explanation>", "severity": "<low|medium|high>" }}
            ]
        }},
        "explanation": [
            "<Bullet point 1 explaining the verdict>",
            "<Bullet point 2>",
            "<Bullet point 3>"
        ]
    }}
    """

    try:
        # 4. Generate Content
        response = model.generate_content(prompt)
        raw_text = response.text

        # 5. Clean & Parse JSON
        # LLMs often wrap JSON in markdown blocks (```json ... ```). We must strip them.
        cleaned_json = raw_text.strip().replace("```json", "").replace("```", "")
        parsed_data = json.loads(cleaned_json)
        
        return parsed_data

    except Exception as e:
        print(f"❌ AI Engine Error: {e}")
        return get_fallback_response()

def get_fallback_response():
    """
    Returns a safe default structure if the AI fails (offline/error).
    This prevents the Backend from crashing.
    """
    return {
        "risk_score": 0,
        "verdict": "ERROR",
        "verdict_color": "#808080",
        "confidence": 0.0,
        "analysis": {
            "psychological_triggers": [],
            "technical_flags": []
        },
        "explanation": [
            "AI analysis is currently unavailable.",
            "Please rely on the static analysis flags above."
        ]
    }

# --- TEST BLOCK (Run this file directly to test) ---
if __name__ == "__main__":
    print("Testing AI Engine...")
    test_text = "URGENT: Your account is suspended. Click bit.ly/123 to verify."
    test_signals = {"regex_hits": ["urgent", "suspended"], "urls": ["bit.ly/123"]}
    
    result = analyze_with_ai(test_text, test_signals)
    print(json.dumps(result, indent=2))