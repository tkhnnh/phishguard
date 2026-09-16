from pydantic import BaseModel

class EmailIn(BaseModel):
    sender: str
    reply_to: str | None = None
    subject: str
    body_text: str
    urls: list[str] = []
    spf_pass: bool | None = None
    
    
   
class Signal(BaseModel):
    code: str
    message: str
    weight: int
    severity: str
    
    
class AnalyzeResponse(BaseModel):
    score: int
    verdict: str
    signals: list[Signal]
    
