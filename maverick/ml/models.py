"""Data models for MAVERICK Machine Learning Phishing Classifier (Module 4)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class InfluentialTerm(BaseModel):
    """Represents a lexical feature contributing to the classification decision."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    term: str = Field(description="Lexical token identified in the email body")
    weight: float = Field(description="Learned model coefficient for this feature")
    tfidf: float = Field(description="Computed TF-IDF score for this token in the document")
    impact: float = Field(description="Net contribution score (weight * tfidf)")
    indicator: str = Field(default="PHISHING", description="Directional indicator: 'PHISHING' or 'BENIGN'")


class MLClassificationResult(BaseModel):
    """Structured ML inference result returned by MAVERICK Module 4."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    phishing_probability: float = Field(
        description="Calibrated threat probability score between 0.0 (benign) and 1.0 (phishing)"
    )
    predicted_label: str = Field(
        description="Categorical decision: 'phishing' or 'benign'"
    )
    confidence: float = Field(
        description="Maximum probability associated with the predicted class"
    )
    top_influential_terms: List[InfluentialTerm] = Field(
        default_factory=list,
        description="Top lexical features driving the model decision for the predicted class"
    )
    cleaned_text_length: int = Field(
        default=0,
        description="Character length of preprocessed body text analyzed"
    )
    model_name: str = Field(
        default="TF-IDF + Logistic Regression",
        description="Model architecture identifier"
    )

    def to_api_dict(self) -> Dict[str, Any]:
        """Serialize result to standard dictionary."""
        return self.model_dump()
