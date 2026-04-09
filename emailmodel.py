#emailmodel.py
import os
import torch
from transformers import BertForSequenceClassification, BertTokenizer

# ─── Paths ────────────────────────────────────────────────────────────────
MODEL_FOLDER = "bert_model"
MODEL_PATH   = os.path.join(MODEL_FOLDER, "model")       # folder, not file
TOKENIZER_PATH = os.path.join(MODEL_FOLDER, "tokenizer") # folder, not file

HF_MODEL_NAME = "ElSlay/BERT-Phishing-Email-Model"

os.makedirs(MODEL_FOLDER, exist_ok=True)

# ─── Load from cache or download ─────────────────────────────────────────
if os.path.exists(MODEL_PATH) and os.path.exists(TOKENIZER_PATH):
    print("✅ Loading cached BERT model...")
    model     = BertForSequenceClassification.from_pretrained(MODEL_PATH)
    tokenizer = BertTokenizer.from_pretrained(TOKENIZER_PATH)
else:
    print("⏳ Downloading BERT model (first run only)...")
    model     = BertForSequenceClassification.from_pretrained(HF_MODEL_NAME)
    tokenizer = BertTokenizer.from_pretrained(HF_MODEL_NAME)

    # Save locally for next time
    model.save_pretrained(MODEL_PATH)
    tokenizer.save_pretrained(TOKENIZER_PATH)
    print(f"✅ Model cached to '{MODEL_FOLDER}/'")

model.eval()

# ─── GPU support (uses CUDA if available, else CPU) ───────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model  = model.to(device)
print(f"🖥️  Running on: {device}")

# ─── Predict function ─────────────────────────────────────────────────────
def predict_email(text: str) -> dict:
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=512
    )
    # Move inputs to same device as model
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs     = model(**inputs)
        logits      = outputs.logits
        prediction  = torch.argmax(logits, dim=-1).item()
        confidence  = torch.softmax(logits, dim=-1).max().item()

    return {
        "label":      "🚨 Phishing" if prediction == 1 else "✅ Legitimate",
        "prediction": prediction,
        "confidence": f"{confidence:.2%}",
    }

