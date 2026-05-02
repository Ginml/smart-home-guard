from pathlib import Path
import logging

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from backend.models.enums import ClassLabel

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "notebooks" / "models"


class MLService:
    def __init__(self, model_path: Path = MODEL_DIR):
        self.model: XGBClassifier | None = None
        self.scaler = None
        self.label_encoder = None
        self.model_path = model_path

    def load(self) -> None:
        """Load model, scaler, and label encoder from disk."""
        logger.info("Loading ML artifacts from %s", self.model_path)

        self.model = XGBClassifier()
        self.model.load_model(str(self.model_path / "xgboost.json"))
        self.scaler = joblib.load(self.model_path / "scaler.pkl")
        self.label_encoder = joblib.load(self.model_path / "label_encoder.pkl")

        logger.info(
            "Model loaded — classes: %s", list(self.label_encoder.classes_)
        )

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def predict(self, features_df: pd.DataFrame) -> list[dict]:
        """Scale features, run inference, return predictions with confidence."""
        scaled = self.scaler.transform(features_df)
        probabilities = self.model.predict_proba(scaled)  # (n_samples, n_classes)
        predicted_indices = np.argmax(probabilities, axis=1)
        categories = self.label_encoder.inverse_transform(predicted_indices)
        confidences = np.max(probabilities, axis=1)

        results = []
        for i in range(len(categories)):
            results.append({
                "predicted_category": ClassLabel(categories[i]),
                "confidence": round(float(confidences[i]), 4),
                "probabilities": {
                    ClassLabel(cls).value: round(float(probabilities[i][j]), 4)
                    for j, cls in enumerate(self.label_encoder.classes_)
                },
            })
        return results
