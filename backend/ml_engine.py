from transformers import pipeline
import json

# Load a tiny, pre-trained spam detection model (Runs locally, no internet needed after 1st run)
# Model: https://huggingface.co/mrm8488/bert-tiny-finetuned-sms-spam-detection
print("⏳ Loading ML Model... (This happens once)")
spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")
print("✅ ML Model Loaded!")

def analyze_with_ml(text: str, signals: dict) -> dict:
    # 1. Run the ML Model
    prediction = spam_classifier(text[:512])[0]
    is_spam = prediction['label'] == 'LABEL_1'
    confidence = prediction['score']
    
    # 2. Base Risk Calculation
    # If ML says Spam, start high. If Safe, start low.
    risk_score = int(confidence * 80) if is_spam else int((1 - confidence) * 10)

    # 3. HEURISTIC RULES (This fixes your issue)
    regex_hits = signals.get("regex_hits", [])
    triggers = []
    explanation = []

    # Rule: Financial Keywords (High Risk)
    financial_words = ["otp", "bank", "password", "verify", "account", "pin"]
    if any(x in regex_hits for x in financial_words):
        risk_score += 30  # FORCE score up by 30
        triggers.append({"type": "Financial", "description": "Requests sensitive financial or login info."})
        explanation.append("The message asks for sensitive security details (OTP/Password).")

    # Rule: Reward/Bait Keywords (Medium Risk)
    bait_words = ["won", "winner", "prize", "reward", "claim", "lottery"]
    if any(x in regex_hits for x in bait_words):
        risk_score += 25  # FORCE score up by 25
        triggers.append({"type": "Scam Bait", "description": "Promises unrealistic rewards."})
        explanation.append("The message claims you have won a prize (common phishing tactic).")

    # Rule: Urgency Keywords (Medium Risk)
    urgency_words = ["urgent", "immediate", "suspended"]
    if any(x in regex_hits for x in urgency_words):
        risk_score += 20
        triggers.append({"type": "Urgency", "description": "Uses pressure to force action."})

    # Rule: Safe Browsing
    if signals.get("safe_browsing") == "flagged":
        risk_score = 100
        triggers.append({"type": "Malware", "description": "URL detected in Google Threat Database."})

    # 4. Final Score Math
    risk_score = min(risk_score, 100) # Cap at 100
    
    # Define Verdict based on the new higher score
    if risk_score > 75:
        verdict = "HIGH_RISK"
        color = "#FF4B4B" # Red
    elif risk_score > 40:
        verdict = "SUSPICIOUS"
        color = "#FFA500" # Orange
    else:
        verdict = "SAFE"
        color = "#00C851" # Green

    # Add ML explanation at the top
    if is_spam:
        explanation.insert(0, f"ML Model detected spam patterns (Confidence: {int(confidence*100)}%).")
    else:
        explanation.insert(0, "ML Model analysis indicates this text follows normal communication patterns.")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_color": color,
        "confidence": round(confidence, 2),
        "analysis": {
            "psychological_triggers": triggers,
            "technical_flags": [
                {"type": "Keywords", "description": f"Found: {', '.join(regex_hits)}", "severity": "medium"} if regex_hits else None
            ]
        },
        "explanation": explanation
    }

if __name__ == "__main__":
    test = "URGENT: Your account is suspended. Click here."
    print(analyze_with_ml(test, {"regex_hits": ["urgent"], "safe_browsing": "clean"}))