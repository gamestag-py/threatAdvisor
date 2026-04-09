"""
Phishing Detection Server - FastAPI
Models are loaded once at startup and reused for all requests
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re

# ─── Load Models at Startup ─────────────────────────────────────────────
# These models are loaded once when server starts and reused for all requests
# from models import predict_url, MODEL_CLEANED, MODEL_PHIUSIIL
from emailmodel import predict_email
from models import predict_url , load_all_models

app = FastAPI()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("\n" + "="*60)
print("✅ SERVER INITIALIZED - ALL MODELS LOADED AND READY!")
print("="*60)
# print(f"  • URL Model 1 (Cleaned): {'✅ Loaded' if MODEL_CLEANED else '❌ Failed'}")
# print(f"  • URL Model 2 (PhiUSIIL): {'✅ Loaded' if MODEL_PHIUSIIL else '❌ Failed'}")
print("  • Email Model (BERT): ✅ Loaded")
print("="*60 + "\n")


all_models = load_all_models()
print(all_models)
print(predict_url("https://amazon.com" , all_models["1"]))
# ─── Request Models ───────────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str
    model: str = "phiusiil"  # default model


class EmailRequest(BaseModel):
    email: str


# ----------- Utility Functions -----------

def is_suspicious_url(url: str , model = "1") -> bool:
    selected_model = all_models[model]
    r = predict_url(url, selected_model)
    return r



def is_suspicious_email(email: str) -> bool:
    result = predict_email(email)
    return result


# ----------- Routes -----------

@app.post("/check/url")
def check_url(data: URLRequest):
    try:
        result = is_suspicious_url(data.url)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/check/email")
def check_email(data: EmailRequest):
    try:
        result = is_suspicious_email(data.email)

        return {
            "input": data.email,
            "type": "email",
            "is_phishing": "Phishing" if result['prediction'] == 1 else "Safe",
            "label": result['label'],
            "confidence": result['confidence']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    


@app.get("/health")
def health():
    try:
        return "Working!"
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))