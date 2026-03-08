"""Tests for ML Detector."""
import unittest
from ml.detector import Detector

class TestDetector(unittest.TestCase):
    def test_no_model_returns_normal(self):
        det = Detector(model_path="ml/models/nonexistent.pkl")
        label, conf = det.predict([0.0] * 20)
        self.assertEqual(label, "NORMAL")
        self.assertEqual(conf, 0.0)

if __name__ == "__main__":
    unittest.main()
