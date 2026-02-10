from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uuid
import time
from schemas import FraudResponse, FraudRequest
# --- UPDATED IMPORTS ---
# We now import the analysis logic directly from your updated engine
from ml_engine import analyze_with_ml 
from utils import sanitize_text, extract_signals, check_safe_browsing, translate_to_english

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.post("/analyze", response_model=FraudResponse)
async def analyze_fraud(request: FraudRequest):
    start_time = time.time()
    
    # --- 1. TRANSLATION LAYER ---
    # Translate first so the ML model understands non-English input
    trans_result = translate_to_english(request.text)
    text_to_analyze = trans_result["translated"]
    
    # --- 2. SANITIZE & SIGNAL EXTRACTION ---
    # Use the TRANSLATED text for analysis
    clean_text = sanitize_text(text_to_analyze)
    signals = extract_signals(text_to_analyze) # This now uses your expanded keyword list
    
    # Check Safe Browsing if URLs exist
    if signals["urls"]:
        signals["safe_browsing"] = check_safe_browsing(signals["urls"])
    else:
        signals["safe_browsing"] = "clean"
    
    # --- 3. RUN ANALYSIS (Using the improved ml_engine.py) ---
    # This calls the function where you added the +30 / +25 score penalties
    ml_result = analyze_with_ml(clean_text, signals)
    
    # --- 4. APPEND MULTILINGUAL FLAGS ---
    if trans_result["is_translated"]:
        # Ensure technical_flags list exists before appending
        if "technical_flags" not in ml_result["analysis"]:
             ml_result["analysis"]["technical_flags"] = []
             
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