from pydantic import BaseModel
from typing import List, Optional

class Trigger(BaseModel):
    type: str
    description: str

class TechFlag(BaseModel):
    type: str
    description: str
    severity: str

class Signals(BaseModel):
    regex_hits: List[str]
    safe_browsing: str
    phone_check: str
    llm_confidence: float

class Analysis(BaseModel):
    psychological_triggers: List[Trigger]
    technical_flags: List[TechFlag]
    signals: Signals

class Result(BaseModel):
    risk_score: int
    verdict: str
    verdict_color: str
    confidence: float

class FraudResponse(BaseModel):
    status: str
    request_id: str
    input_type: str
    sanitized_input: str
    result: Result
    analysis: Analysis
    explanation: List[str]
    processing_time_ms: int
