from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from schemas import FraudResponse, FraudRequest
from utils import sanitize_text, extract_signals
from ai_engine import analyze_with_ai  # <--- NEW IMPORT
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
    
    # 2. REAL AI ANALYSIS (Replaces the mock logic)
    ai_result = analyze_with_ai(clean_text, signals)
    
    processing_time = int((time.time() - start_time) * 1000)
    
    # 3. Merge AI result with our response schema
    return {
        "status": "success",
        "request_id": str(uuid.uuid4()),
        "input_type": "text",
        "sanitized_input": clean_text,
        "result": {
            "risk_score": ai_result.get("risk_score", 0),
            "verdict": ai_result.get("verdict", "Unknown").upper(),
            "verdict_color": "#FF4B4B" if ai_result.get("risk_score", 0) > 70 else "#00C851",
            "confidence": 0.95
        },
        "analysis": {
            "psychological_triggers": ai_result.get("analysis", {}).get("psychological_triggers", []),
            "technical_flags": ai_result.get("analysis", {}).get("technical_flags", []),
            "signals": {
                "regex_hits": signals["regex_hits"],
                "safe_browsing": "unchecked",
                "phone_check": "unchecked",
                "llm_confidence": 0.9
            }
        },
        "explanation": ai_result.get("explanation", []),
        "processing_time_ms": processing_time
    }
