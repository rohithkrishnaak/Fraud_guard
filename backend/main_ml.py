from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from transformers import pipeline
import uuid
import time
from schemas import FraudResponse, FraudRequest
# --- UPDATED IMPORT ---
from utils import sanitize_text, extract_signals, check_safe_browsing, translate_to_english

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

print("⏳ Loading ML Model...")
spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")
print("✅ ML Model Loaded!")

def analyze_with_ml_logic(text: str, signals: dict) -> dict:
    # 1. BERT Model Analysis
    prediction = spam_classifier(text[:512])[0]
    is_spam = prediction['label'] == 'LABEL_1'
    confidence = prediction['score']
    
    # Base Score from ML Model
    risk_score = int(confidence * 100) if is_spam else int((1 - confidence) * 20)
    
    explanation = []
    triggers = []
    
    # 2. Logic Rules (These now INCREASE the score)
    regex_hits = signals.get("regex_hits", [])

    # Rule: Urgency
    if any(x in ["urgent", "immediate", "suspended", "deadline"] for x in regex_hits):
        risk_score += 25  # Penalize for urgency
        triggers.append({"type": "Urgency", "description": "High-pressure language detected."})
        explanation.append("Message uses urgency tactics to force action.")

    # Rule: Financial / Sensitive
    if any(x in ["bank", "verify", "account", "irs", "password", "otp"] for x in regex_hits):
        risk_score += 20  # Penalize for sensitive keywords
        triggers.append({"type": "Financial", "description": "Requests sensitive financial or login info."})

    # Rule: Domain Age
    domain_age = signals.get("domain_age")
    if domain_age is not None:
        if domain_age > -1 and domain_age < 30:
            risk_score += 40
            triggers.append({"type": "New Domain", "description": f"Website is only {domain_age} days old."})
            explanation.append(f"HIGH RISK: The domain was registered only {domain_age} days ago.")
        elif domain_age > 3650: # 10 years
            risk_score -= 10
            explanation.append(f"Domain is trusted (aged {domain_age} days).")

    # Rule: Safe Browsing
    if signals.get("safe_browsing") == "flagged":
        risk_score = 99
        triggers.append({"type": "Malware", "description": "Google Safe Browsing Flag."})
    
    # 3. Finalize Score
    risk_score = max(0, min(100, risk_score))
    
    if risk_score > 75: verdict = "HIGH_RISK"; color = "#FF4B4B"
    elif risk_score > 40: verdict = "SUSPICIOUS"; color = "#FFA500"
    else: verdict = "SAFE"; color = "#00C851"

    if is_spam: explanation.append(f"ML Model detected spam patterns.")
    else: explanation.append("ML Model sees normal patterns.")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_color": color,
        "confidence": round(confidence, 2),
        "analysis": {
            "psychological_triggers": triggers,
            "technical_flags": []
        },
        "explanation": explanation
    }

@app.post("/analyze", response_model=FraudResponse)
async def analyze_fraud(request: FraudRequest):
    start_time = time.time()
    
    # --- 1. TRANSLATION LAYER (NEW) ---
    # Translate first so the ML model understands non-English input
    trans_result = translate_to_english(request.text)
    text_to_analyze = trans_result["translated"]
    
    # --- 2. SANITIZE & SIGNAL EXTRACTION ---
    # Use the TRANSLATED text for analysis
    clean_text = sanitize_text(text_to_analyze)
    signals = extract_signals(text_to_analyze)
    
    if signals["urls"]:
        signals["safe_browsing"] = check_safe_browsing(signals["urls"])
    else:
        signals["safe_browsing"] = "clean"
    
    # --- 3. RUN ANALYSIS ---
    ml_result = analyze_with_ml_logic(clean_text, signals)
    
    # --- 4. APPEND MULTILINGUAL FLAGS ---
    # If we translated it, add a flag so the frontend knows
    if trans_result["is_translated"]:
        ml_result["analysis"]["technical_flags"].append({
            "type": "Multilingual Detection", 
            "description": f"Detected {trans_result['src_lang']}. Analyzed as: '{text_to_analyze[:30]}...'",
            "severity": "low"
        })

    return {
        "status": "success",
        "request_id": str(uuid.uuid4()),
        "input_type": "text",
        "sanitized_input": clean_text,
        "result": {
            "risk_score": ml_result["risk_score"],
            "verdict": ml_result["verdict"],
            "verdict_color": ml_result["verdict_color"],
            "confidence": ml_result["confidence"]
        },
        "analysis": {
            "psychological_triggers": ml_result["analysis"]["psychological_triggers"],
            "technical_flags": ml_result["analysis"]["technical_flags"],
            "signals": {
                "regex_hits": signals["regex_hits"],
                "safe_browsing": signals["safe_browsing"],
                "phone_check": "unchecked",
                "llm_confidence": 0.0,
                "domain_age": signals.get("domain_age") 
            }
        },
        "explanation": ml_result["explanation"],
        "processing_time_ms": int((time.time() - start_time) * 1000)
    }