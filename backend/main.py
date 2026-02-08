from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from schemas import FraudResponse, FraudRequest

from utils import sanitize_text, extract_signals, check_safe_browsing 
from ai_engine import analyze_with_ai
import uuid
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

@app.post("/analyze", response_model=FraudResponse)
async def analyze_fraud(request: FraudRequest):
    start_time = time.time()
    
    # 1. Sanitize & Static Check
    clean_text = sanitize_text(request.text)
    signals = extract_signals(request.text)
    
    # Actually run the Safe Browsing Check
    sb_status = "unchecked"
    if signals["urls"]:
        sb_status = check_safe_browsing(signals["urls"])
    
    # Add this to signals so the AI sees it
    signals["safe_browsing"] = sb_status
    
    #  AI ANALYSIS
    # The AI now gets the safe browsing result in the context
    ai_result = analyze_with_ai(clean_text, signals)
    
    processing_time = int((time.time() - start_time) * 1000)
    
    # 3. Merge results
    return {
        "status": "success",
        "request_id": str(uuid.uuid4()),
        "input_type": "text",
        "sanitized_input": clean_text,
        "result": {
            "risk_score": ai_result.get("risk_score", 0),
            "verdict": ai_result.get("verdict", "UNKNOWN"),
            "verdict_color": ai_result.get("verdict_color", "#808080"),
            "confidence": ai_result.get("confidence", 0.0)
        },
        "analysis": {
            "psychological_triggers": ai_result.get("analysis", {}).get("psychological_triggers", []),
            "technical_flags": ai_result.get("analysis", {}).get("technical_flags", []),
            "signals": {
                "regex_hits": signals["regex_hits"],
                # Return the REAL status, not hardcoded "unchecked"
                "safe_browsing": sb_status, 
                "phone_check": "unchecked", # Placeholder for future logic
                "llm_confidence": ai_result.get("confidence", 0.0)
            }
        },
        "explanation": ai_result.get("explanation", []),
        "processing_time_ms": processing_time
    }
