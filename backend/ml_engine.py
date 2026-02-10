# ml_engine.py
from transformers import pipeline

# Load a tiny, pre-trained spam detection model
print("⏳ Loading ML Model... (This happens once)")
spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")
print("✅ ML Model Loaded!")

def analyze_with_ml(text: str, signals: dict) -> dict:
    # 1. Run the ML Model
    prediction = spam_classifier(text[:512])[0]
    is_spam = prediction['label'] == 'LABEL_1'
    confidence = prediction['score']
    
    # 2. Base Risk Calculation
    risk_score = int(confidence * 80) if is_spam else int((1 - confidence) * 10)

    # 3. HEURISTIC RULES
    regex_hits = signals.get("regex_hits", [])
    triggers = []
    explanation = []

    # Rule: Financial Keywords (High Risk)
    financial_words = ["otp", "bank", "password", "verify", "account", "pin"]
    if any(x in regex_hits for x in financial_words):
        risk_score += 30 
        triggers.append({"type": "Financial", "description": "Requests sensitive financial or login info."})
        explanation.append("The message asks for sensitive security details (OTP/Password).")

    # Rule: Reward/Bait Keywords (Medium Risk)
    bait_words = ["won", "winner", "prize", "reward", "claim", "lottery", "cash", "free", "whatsapp"]
    if any(x in regex_hits for x in bait_words):
        risk_score += 25 
        triggers.append({"type": "Scam Bait", "description": "Promises unrealistic rewards."})
        explanation.append("The message claims you have won a prize (common phishing tactic).")

    # Rule: Urgency Keywords (Medium Risk)
    urgency_words = ["urgent", "immediate", "suspended", "deadline", "alert"] 
    if any(x in regex_hits for x in urgency_words):
        risk_score += 20
        triggers.append({"type": "Urgency", "description": "Uses pressure to force action."})

    # Rule: Suspicious TLD (The "Zero-Day" Catcher) <--- NEW RULE
    if signals.get("suspicious_tld"):
        risk_score += 40  # Massive penalty for sketchy domains
        triggers.append({"type": "Suspicious Link", "description": "URL uses a high-risk domain extension (.cc/.xyz)."})
        explanation.append("The link uses a domain ending commonly associated with spam/scams.")

    # Rule: Safe Browsing
    if signals.get("safe_browsing") == "flagged":
        risk_score = 100
        triggers.append({"type": "Malware", "description": "URL detected in Google Threat Database."})

   # 4. Final Score Math
    risk_score = min(risk_score, 100)
    
    # --- UPDATED THRESHOLDS ---
    if risk_score >= 75:        # Changed > to >= (includes 75)
        verdict = "HIGH_RISK"
        color = "#FF4B4B"       # Red
    elif risk_score >= 35:      # LOWERED from 40 to 35. Now 35-74 is "Suspicious"
        verdict = "SUSPICIOUS"
        color = "#FFA500"       # Orange
    elif risk_score >= 15:      # OPTIONAL: A new "Low Risk" middle ground
        verdict = "POTENTIAL_RISK"
        color = "#FFD700"       # Gold/Yellow
    else:
        verdict = "SAFE"
        color = "#00C851"       # Green

    if is_spam:
        explanation.insert(0, f"ML Model detected spam patterns (Confidence: {int(confidence*100)}%).")
    else:
        explanation.insert(0, "ML Model analysis indicates this text follows normal communication patterns.")

    # Build Technical Flags (No crashes!)
    tech_flags = []
    if regex_hits:
        tech_flags.append({
            "type": "Keywords", 
            "description": f"Found: {', '.join(regex_hits)}", 
            "severity": "medium"
        })
    # Add flag for suspicious TLD
    if signals.get("suspicious_tld"):
        tech_flags.append({
            "type": "Domain Check",
            "description": "Detected high-risk Top Level Domain (e.g. .cc, .xyz)",
            "severity": "high"
        })

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_color": color,
        "confidence": round(confidence, 2),
        "analysis": {
            "psychological_triggers": triggers,
            "technical_flags": tech_flags
        },
        "explanation": explanation
    }