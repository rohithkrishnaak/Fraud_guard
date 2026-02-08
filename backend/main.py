from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from schemas import FraudResponse, FraudRequest
import uuid
import time

app = FastAPI(title="Fraud Guard API")

# CRITICAL: Allow CORS so Frontend (running on a different port) can talk to Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

@app.get("/")
def home():
    return {"message": "Fraud Guard API is running"}

@app.post("/analyze", response_model=FraudResponse)
async def analyze_fraud(request: FraudRequest):
    """
    MOCK ENDPOINT: Returns hardcoded data to unblock frontend development.
    """
    # Simulate processing delay
    time.sleep(1) 
    
    return {
        "status": "success",
        "request_id": str(uuid.uuid4()),
        "input_type": "text",
        "sanitized_input": "Your account [REDACTED] is blocked...",
        "result": {
            "risk_score": 88,
            "verdict": "HIGH_RISK",
            "verdict_color": "#FF4B4B",
            "confidence": 0.95
        },
        "analysis": {
            "psychological_triggers": [
                {"type": "Urgency", "description": "Demands immediate action using phrases like 'verify now'."},
                {"type": "Authority Impersonation", "description": "Falsely claims to be from Cyber Police."}
            ],
            "technical_flags": [
                {"type": "Malicious Link", "description": "Shortened URL redirects to a known phishing domain.", "severity": "high"}
            ],
            "signals": {
                "regex_hits": ["verify now", "suspended"],
                "safe_browsing": "flagged",
                "phone_check": "unknown",
                "llm_confidence": 0.9
            }
        },
        "explanation": [
            "The message creates panic to force quick action.",
            "It impersonates an authority figure to gain trust.",
            "The included link is associated with phishing activity."
        ],
        "processing_time_ms": 1024
    }