"""
MAVERICK — Machine Learning Prediction Engine & FastAPI Microservice
Smart India Hackathon 2026
"""

import os
import sys
import re
import json
import argparse
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
# pyrefly: ignore [missing-import]
import joblib

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# Ensure repository root is on sys.path for direct module imports
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

def clean_text(text: str) -> str:
    """
    Standard text preprocessing pipeline:
    - Lowercasing
    - Stripping URLs, HTML tags, email addresses
    - Removing non-alphanumeric punctuation
    - Normalizing whitespaces
    """
    if not isinstance(text, str):
        return ""
    
    text = text.lower()
    text = re.sub(r'<[^>]+>', ' ', text)  # strip HTML tags
    text = re.sub(r'https?://\S+|www\.\S+', ' url_token ', text)  # normalize URLs
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' email_token ', text)
    text = re.sub(r'[^a-zA-Z0-9_\s]', ' ', text)  # keep words and tokens
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# Robust project-relative paths with environment variable override support
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(BASE_DIR, "model"))
VEC_PATH = os.environ.get("VECTORIZER_PATH", os.path.join(MODEL_DIR, "vectorizer.pkl"))
MODEL_PATH = os.environ.get("MODEL_PATH", os.path.join(MODEL_DIR, "phishing_model.pkl"))

# Global cached model instances
_vectorizer = None
_model = None
_model_load_error = None

def load_artifacts(force_reload: bool = False):
    global _vectorizer, _model, _model_load_error
    if force_reload or _vectorizer is None or _model is None:
        if not os.path.exists(VEC_PATH) or not os.path.exists(MODEL_PATH):
            _model_load_error = (
                f"Model artifacts missing. Expected vectorizer at '{VEC_PATH}' "
                f"and model at '{MODEL_PATH}'."
            )
            raise FileNotFoundError(_model_load_error)
        try:
            _vectorizer = joblib.load(VEC_PATH)
            _model = joblib.load(MODEL_PATH)
            _model_load_error = None
        except Exception as e:
            _model_load_error = f"Failed to load model artifacts: {str(e)}"
            raise RuntimeError(_model_load_error) from e
    return _vectorizer, _model

# Eagerly attempt to load artifacts on module import if available
try:
    load_artifacts()
except Exception:
    pass

def predict_threat(text: str) -> Dict[str, Any]:
    """
    Perform genuine ML inference on raw email text.
    Handles empty, very short, and edge-case inputs gracefully.
    """
    # 1. Input validation
    if text is None or not isinstance(text, str):
        return {
            "prediction": "unknown",
            "phishing_probability": 0.0,
            "legitimate_probability": 0.0,
            "confidence": 0.0,
            "model": "TF-IDF + Logistic Regression",
            "error": "Input must be a non-null string",
            "status": "INVALID_INPUT"
        }

    cleaned = clean_text(text)
    if len(cleaned.strip()) < 3:
        return {
            "prediction": "legitimate",
            "phishing_probability": 0.05,
            "legitimate_probability": 0.95,
            "confidence": 0.95,
            "model": "TF-IDF + Logistic Regression",
            "top_features": [],
            "note": "Text length too short for high-confidence lexical analysis",
            "status": "SUCCESS"
        }

    # 2. Load model
    vectorizer, model = load_artifacts()

    # 3. Vectorize text
    vec = vectorizer.transform([cleaned])

    # 4. Predict class & probability
    probs = model.predict_proba(vec)[0]
    legit_prob = float(probs[0])
    phish_prob = float(probs[1])
    predicted_class = "phishing" if phish_prob >= 0.5 else "legitimate"

    # 5. Extract active TF-IDF terms in this email with their learned model coefficients
    feature_names = vectorizer.get_feature_names_out()
    coefs = model.coef_[0]
    non_zero_indices = vec.nonzero()[1]

    contributing_terms = []
    for idx in non_zero_indices:
        term = feature_names[idx]
        tfidf_val = vec[0, idx]
        coef_val = coefs[idx]
        contribution = tfidf_val * coef_val
        contributing_terms.append({
            "term": term,
            "weight": round(float(coef_val), 4),
            "tfidf": round(float(tfidf_val), 4),
            "impact": round(float(contribution), 4),
            "indicator": "PHISHING" if coef_val > 0 else "BENIGN"
        })

    # Sort terms by absolute impact
    contributing_terms.sort(key=lambda x: abs(x["impact"]), reverse=True)

    return {
        "prediction": predicted_class,
        "phishing_probability": round(phish_prob, 4),
        "legitimate_probability": round(legit_prob, 4),
        "confidence": round(max(phish_prob, legit_prob), 4),
        "model": "TF-IDF + Logistic Regression",
        "top_features": contributing_terms[:8],
        "status": "SUCCESS"
    }

# ----------------------------------------------------------------------
# FastAPI Microservice Definition
# ----------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Eagerly ensure artifacts are loaded when application starts
    try:
        load_artifacts()
        print(f"[+] Loaded ML model from {MODEL_PATH} and vectorizer from {VEC_PATH}")
    except Exception as e:
        print(f"[!] Warning: Failed to load model artifacts on startup: {e}", file=sys.stderr)
    yield

app = FastAPI(
    title="MAVERICK AI Threat Detection Service",
    description="Real ML TF-IDF + Logistic Regression Phishing Classifier API (SIH 2026)",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PredictRequest(BaseModel):
    text: Optional[str] = Field(default="", description="Email subject and body text to analyze")

class PredictResponse(BaseModel):
    prediction: str
    phishing_probability: float
    legitimate_probability: float
    model: str
    confidence: Optional[float] = None
    top_features: Optional[List[Dict[str, Any]]] = None
    status: Optional[str] = None
    note: Optional[str] = None

@app.get("/")
def root_endpoint():
    return {
        "service": "MAVERICK ML Inference Engine",
        "version": "1.0.0",
        "model": "TF-IDF + Logistic Regression",
        "endpoints": {
            "health": "/health",
            "predict": "/predict",
            "docs": "/docs"
        }
    }

@app.get("/health")
def health_check():
    loaded = False
    error = None
    try:
        vec, mdl = load_artifacts()
        loaded = (vec is not None and mdl is not None)
    except Exception as e:
        loaded = False
        error = str(e)

    if not loaded or _model is None or _vectorizer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "service": "MAVERICK ML Inference Engine",
                "model_loaded": False,
                "error": error or _model_load_error or "Model artifacts could not be loaded",
                "vectorizer_path": VEC_PATH,
                "model_path": MODEL_PATH
            }
        )

    return {
        "status": "healthy",
        "service": "MAVERICK ML Inference Engine",
        "model_type": "TF-IDF + Logistic Regression",
        "model_loaded": True,
        "vocabulary_size": len(_vectorizer.vocabulary_) if hasattr(_vectorizer, "vocabulary_") else None,
        "vectorizer_path": VEC_PATH,
        "model_path": MODEL_PATH
    }

@app.post("/predict", response_model=PredictResponse)
def predict_endpoint(req: PredictRequest):
    try:
        result = predict_threat(req.text or "")
        if result.get("status") == "INVALID_INPUT":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.get("error"))
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Prediction failure: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAVERICK ML Inference Tool")
    parser.add_argument("--text", type=str, help="Email text to evaluate")
    parser.add_argument("--serve", action="store_true", help="Start FastAPI HTTP prediction server")
    default_host = os.environ.get("HOST", "0.0.0.0")
    default_port = int(os.environ.get("PORT", 8000))
    parser.add_argument("--host", default=default_host, help="Host address (default: 0.0.0.0 or $HOST)")
    parser.add_argument("--port", type=int, default=default_port, help="Port number (default: 8000 or $PORT)")
    args = parser.parse_args()

    if args.serve:
        host = os.environ.get("HOST", args.host)
        port = int(os.environ.get("PORT", args.port))
        print(f"[*] Starting MAVERICK ML Inference Service on http://{host}:{port}")
        uvicorn.run(app, host=host, port=port)
    elif args.text is not None:
        result = predict_threat(args.text)
        print(json.dumps(result, indent=2))
    else:
        # Default demo prediction
        sample = "URGENT: Wire transfer authorization required immediately. Statutory allocation directive applies."
        print(f"[*] Sample Input: {sample}")
        print("[*] Running ML Inference...")
        result = predict_threat(sample)
        print(json.dumps(result, indent=2))
