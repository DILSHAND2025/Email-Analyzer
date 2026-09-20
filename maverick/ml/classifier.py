"""Machine Learning Phishing Classifier Engine for MAVERICK (Module 4)."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from maverick.ml.models import InfluentialTerm, MLClassificationResult
from maverick.parser.models import ParsedEmail

# Default paths for model artifacts
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
DEFAULT_VEC_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")
DEFAULT_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")


def clean_text(text: Optional[str]) -> str:
    """
    Standard text preprocessing pipeline matching model training:
    - Lowercase
    - Strip HTML tags
    - Normalize URLs to 'url_token'
    - Normalize emails to 'email_token'
    - Filter non-alphanumeric punctuation
    - Normalize whitespace
    """
    if not text or not isinstance(text, str):
        return ""

    s = text.lower()
    s = re.sub(r"<[^>]+>", " ", s)  # strip HTML tags
    s = re.sub(r"https?://\S+|www\.\S+", " url_token ", s)  # normalize URLs
    s = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", " email_token ", s
    )  # normalize emails
    s = re.sub(r"[^a-zA-Z0-9_\s]", " ", s)  # keep word tokens
    s = re.sub(r"\s+", " ", s).strip()
    return s


class MLClassifier:
    """
    Singleton inference wrapper for pre-trained TF-IDF vectorizer and classification model.
    Loads artifacts into memory once at startup (not per-request).
    """

    def __init__(
        self,
        vectorizer_path: Optional[str] = None,
        model_path: Optional[str] = None,
        auto_load: bool = True,
    ):
        self.vectorizer_path = vectorizer_path or DEFAULT_VEC_PATH
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.vectorizer = None
        self.model = None
        self.is_loaded = False
        self.load_error: Optional[str] = None

        if auto_load:
            self.load()

    def load(self, force: bool = False) -> None:
        """Load vectorizer and model artifacts into memory once."""
        if self.is_loaded and not force:
            return

        if not os.path.exists(self.vectorizer_path):
            self.load_error = f"Vectorizer artifact missing at: {self.vectorizer_path}"
            raise FileNotFoundError(self.load_error)

        if not os.path.exists(self.model_path):
            self.load_error = f"Model artifact missing at: {self.model_path}"
            raise FileNotFoundError(self.load_error)

        try:
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.model = joblib.load(self.model_path)
            self.is_loaded = True
            self.load_error = None
        except Exception as exc:
            self.load_error = f"Failed to load ML artifacts: {exc}"
            self.is_loaded = False
            raise RuntimeError(self.load_error) from exc

    def classify_text(self, text: Optional[str], top_k: int = 8) -> MLClassificationResult:
        """
        Perform inference on raw text string:
        - Vectorizes text using cached TF-IDF vectorizer
        - Predicts class probabilities
        - Extracts top influential lexical terms for the predicted class
        """
        if not self.is_loaded:
            self.load()

        cleaned = clean_text(text)
        cleaned_len = len(cleaned)

        # Handle very short or empty inputs gracefully
        if cleaned_len < 3:
            return MLClassificationResult(
                phishing_probability=0.05,
                predicted_label="benign",
                confidence=0.95,
                top_influential_terms=[],
                cleaned_text_length=cleaned_len,
                model_name=type(self.model).__name__,
            )

        # 1. Transform text to TF-IDF vector
        vec = self.vectorizer.transform([cleaned])

        # 2. Predict probabilities
        probs = self.model.predict_proba(vec)[0]
        # In binary classification: probs[0] = class 0 (benign), probs[1] = class 1 (phishing)
        benign_prob = float(probs[0])
        phishing_prob = float(probs[1])

        is_phishing = phishing_prob >= 0.5
        predicted_label = "phishing" if is_phishing else "benign"
        confidence = max(phishing_prob, benign_prob)

        # 3. Extract influential terms via TF-IDF feature weights
        top_terms = self._extract_influential_terms(vec, predicted_label, top_k=top_k)

        return MLClassificationResult(
            phishing_probability=round(phishing_prob, 4),
            predicted_label=predicted_label,
            confidence=round(confidence, 4),
            top_influential_terms=top_terms,
            cleaned_text_length=cleaned_len,
            model_name=f"TF-IDF + {type(self.model).__name__}",
        )

    def classify_parsed_email(
        self, parsed_email: ParsedEmail, top_k: int = 8
    ) -> MLClassificationResult:
        """Classify a ParsedEmail object by extracting and combining its body content."""
        # Prefer plain text, fall back to HTML or concatenate
        plain = parsed_email.body_plain or ""
        html = parsed_email.body_html or ""
        
        # Combine if both present or choose non-empty
        combined_body = f"{plain}\n{html}".strip() if plain and html else (plain or html)
        return self.classify_text(combined_body, top_k=top_k)

    def _extract_influential_terms(
        self, vec, predicted_label: str, top_k: int = 8
    ) -> List[InfluentialTerm]:
        """
        Extract active lexical terms in the document with their model feature weights
        sorted by their contribution towards the predicted class.
        """
        feature_names = self.vectorizer.get_feature_names_out()
        non_zero_indices = vec.nonzero()[1]

        if len(non_zero_indices) == 0:
            return []

        # Obtain model weights/coefficients
        if hasattr(self.model, "coef_"):
            coefs = self.model.coef_[0]
        elif hasattr(self.model, "coefs_"):
            # Multi-layer perceptron (aggregate first hidden layer weights)
            coefs = np.mean(self.model.coefs_[0], axis=1)
        else:
            coefs = np.zeros(len(feature_names))

        active_terms: List[InfluentialTerm] = []

        for idx in non_zero_indices:
            term = str(feature_names[idx])
            tfidf_val = float(vec[0, idx])
            weight_val = float(coefs[idx])
            impact = weight_val * tfidf_val
            indicator = "PHISHING" if weight_val > 0 else "BENIGN"

            active_terms.append(
                InfluentialTerm(
                    term=term,
                    weight=round(weight_val, 4),
                    tfidf=round(tfidf_val, 4),
                    impact=round(impact, 4),
                    indicator=indicator,
                )
            )

        # Sort terms prioritizing those driving the predicted class
        if predicted_label == "phishing":
            # Highest positive impact drives phishing classification
            phishing_terms = [t for t in active_terms if t.impact > 0]
            phishing_terms.sort(key=lambda x: x.impact, reverse=True)
            if len(phishing_terms) >= top_k:
                return phishing_terms[:top_k]
            # If fewer, supplement with other highest-magnitude terms
            active_terms.sort(key=lambda x: abs(x.impact), reverse=True)
            return active_terms[:top_k]
        else:
            # Most negative impact drives benign classification
            benign_terms = [t for t in active_terms if t.impact < 0]
            benign_terms.sort(key=lambda x: x.impact)  # Most negative first
            if len(benign_terms) >= top_k:
                return benign_terms[:top_k]
            active_terms.sort(key=lambda x: abs(x.impact), reverse=True)
            return active_terms[:top_k]


# Module-level singleton instance loaded once at application startup
_classifier_instance: Optional[MLClassifier] = None


def get_classifier() -> MLClassifier:
    """Get or initialize the shared singleton MLClassifier instance."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = MLClassifier(auto_load=True)
    return _classifier_instance


def classify_text(text: Optional[str], top_k: int = 8) -> MLClassificationResult:
    """Convenience function to classify raw text using the cached ML model."""
    classifier = get_classifier()
    return classifier.classify_text(text, top_k=top_k)


def classify_parsed_email(
    parsed_email: ParsedEmail, top_k: int = 8
) -> MLClassificationResult:
    """Convenience function to classify a ParsedEmail object using the cached ML model."""
    classifier = get_classifier()
    return classifier.classify_parsed_email(parsed_email, top_k=top_k)
