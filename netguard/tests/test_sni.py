"""Tests for SNI Extractor."""
import unittest
from inspector.sni_extractor import extract_sni

class TestSNIExtractor(unittest.TestCase):
    def test_non_tls_returns_none(self):
        self.assertIsNone(extract_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

    def test_empty_returns_none(self):
        self.assertIsNone(extract_sni(b""))

if __name__ == "__main__":
    unittest.main()
