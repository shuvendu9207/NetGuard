"""
ML Detector
Loads a trained model and predicts the label for a feature vector.
"""

import os
import pickle
from typing import Tuple, List

LABELS = ["NORMAL", "PORT_SCAN", "DOS", "BRUTEFORCE", "DATA_EXFIL", "ANOMALY"]


class Detector:
    def __init__(self, model_path: str = "ml/models/model.pkl"):
        self.model = None
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)

    def predict(self, features: List[float]) -> Tuple[str, float]:
        """
        Returns (label, confidence).
        Falls back to ("NORMAL", 0.0) if no model is loaded.
        """
        if self.model is None:
            return "NORMAL", 0.0
        import numpy as np
        x = np.array(features).reshape(1, -1)
        label_idx = int(self.model.predict(x)[0])
        confidence = 0.0
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(x)[0]
            confidence = float(proba[label_idx])
        label = LABELS[label_idx] if label_idx < len(LABELS) else "UNKNOWN"
        return label, confidence
