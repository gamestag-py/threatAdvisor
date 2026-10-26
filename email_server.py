
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from emailmodel import predict_email

app = FastAPI(title="Email Phishing Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    email: str

@app.on_event("startup")
def startup():
    print("Email phishing detection server started.")

@app.post("/check/email")
def check_email(data: EmailRequest):
    try:
        result = predict_email(data.email)

        return {
            "input": data.email,
            "type": "email",
            "is_phishing": (
                "Phishing" if result["prediction"] == 1 else "Safe"
            ),
            "label": result["label"],
            "confidence": result["confidence"],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {"status": "Working!"}
