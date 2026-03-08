"""Tests for BehavioralEngine."""
import unittest
from behavior.behavioral_engine import BehavioralEngine

class TestBehavioralEngine(unittest.TestCase):
    def setUp(self):
        self.engine = BehavioralEngine()

    def test_port_scan_detection(self):
        for port in range(100):
            self.engine.update("1.2.3.4", "10.0.0.1", port, 60, 0x02)
        result = self.engine.evaluate("1.2.3.4")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "PORT_SCAN")

if __name__ == "__main__":
    unittest.main()
