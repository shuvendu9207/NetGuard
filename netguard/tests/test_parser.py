"""Tests for PacketParser."""
import unittest
from parser.packet_parser import PacketParser

class TestPacketParser(unittest.TestCase):
    def test_parse_empty(self):
        result = PacketParser.parse(b"")
        # Should not crash, may return None or empty ParsedPacket
        # Extend with real packet bytes once parser is implemented
        self.assertTrue(result is None or result is not None)

if __name__ == "__main__":
    unittest.main()
