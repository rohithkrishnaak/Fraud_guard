from transformers import pipeline
import json

# Load a tiny, pre-trained spam detection model (Runs locally, no internet needed after 1st run)
# Model: https://huggingface.co/mrm8488/bert-tiny-finetuned-sms-spam-detection
print("⏳ Loading ML Model... (This happens once)")
spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")
print("✅ ML Model Loaded!")

def analyze_with_ml(text: str, signals: dict) -> dict:
    """
    Analyzes text using a Local BERT Model + Logic Rules.
    No API Keys required. No Prompting.
    """
    
    # 1. Run the ML Model
    # Output looks like: [{'label': 'LABEL_1', 'score': 0.98}] (LABEL_1 = Spam, LABEL_0 = Ham)
    prediction = spam_classifier(text[:512])[0] # BERT handles max 512 chars well
    
    is_spam = prediction['label'] == 'LABEL_1'
    confidence = prediction['score']
    
    # 2. Calculate Risk Score (0-100)
    # If ML says Spam, start high. If Safe Browsing flagged it, max it out.
    risk_score = int(confidence * 100) if is_spam else int((1 - confidence) * 20)
    
    if signals.get("safe_browsing") == "flagged":
        risk_score = 99
        is_spam = True

    # 3. Generate Verdict
    if risk_score > 75:
        verdict = "HIGH_RISK"
        color = "#FF4B4B"
    elif risk_score > 40:
        verdict = "SUSPICIOUS"
        color = "#FFA500"
    else:
        verdict = "SAFE"
        color = "#00C851"

    # 4. Generate Explanations (Logic-Based, since ML doesn't speak)
    explanation = []
    triggers = []
    
    # Rule: ML Verdict
    if is_spam:
        explanation.append(f"ML Model detected patterns matching known spam/phishing (Confidence: {int(confidence*100)}%).")
    else:
        explanation.append("ML Model analysis indicates this text follows normal communication patterns.")

    # Rule: Urgency Keywords
    regex_hits = signals.get("regex_hits", [])
    if any(x in ["urgent", "immediate", "suspended"] for x in regex_hits):
        triggers.append({"type": "Urgency", "description": "Uses high-pressure language to force action."})
        explanation.append("Message uses urgency tactics to bypass critical thinking.")

    # Rule: Financial Keywords
    if any(x in ["bank", "verify", "account", "irs"] for x in regex_hits):
        triggers.append({"type": "Financial", "description": "Requests sensitive financial actions."})
    
    # Rule: Safe Browsing
    if signals.get("safe_browsing") == "flagged":
        triggers.append({"type": "Malware", "description": "Link matches Google Threat Database."})
        explanation.append("The link provided is confirmed malicious by Google Safe Browsing.")

    # 5. Construct Final JSON
    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_color": color,
        "confidence": round(confidence, 2),
        "analysis": {
            "psychological_triggers": triggers,
           # NEW LOGIC: Only add the dictionary if the condition is true
            "technical_flags": [
                item for item in [
                    {"type": "Keywords", "description": f"Found: {', '.join(regex_hits)}", "severity": "medium"} if regex_hits else None,
                    {"type": "ML Detection", "description": "Pattern matches spam dataset", "severity": "high"} if is_spam else None
                ] if item is not None
            ]
        },
        "explanation": explanation
    }

# Test Block
if __name__ == "__main__":
    test = "URGENT: Your account is suspended. Click here."
    print(analyze_with_ml(test, {"regex_hits": ["urgent"], "safe_browsing": "clean"}))