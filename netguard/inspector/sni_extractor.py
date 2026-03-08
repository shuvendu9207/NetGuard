"""
SNI Extractor
Parses TLS Client Hello to extract the Server Name Indication hostname.
Works on raw TCP payload bytes — no external libraries needed.
"""

from typing import Optional


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Returns the SNI hostname from a TLS Client Hello payload,
    or None if not found / not a Client Hello.
    """
    try:
        if len(payload) < 6:
            return None
        # Content type 0x16 = Handshake
        if payload[0] != 0x16:
            return None
        # Handshake type 0x01 = Client Hello
        if payload[5] != 0x01:
            return None

        offset = 43  # skip fixed Client Hello header fields

        # Skip Session ID
        if offset >= len(payload):
            return None
        session_len = payload[offset]
        offset += 1 + session_len

        # Skip Cipher Suites
        if offset + 2 > len(payload):
            return None
        cipher_len = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2 + cipher_len

        # Skip Compression Methods
        if offset >= len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions length
        if offset + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2
        ext_end = offset + ext_total

        while offset + 4 <= ext_end:
            ext_type = int.from_bytes(payload[offset:offset+2], "big")
            ext_len  = int.from_bytes(payload[offset+2:offset+4], "big")
            offset  += 4

            if ext_type == 0x0000:  # SNI extension
                # SNI list length (2) + entry type (1) + name length (2)
                if offset + 5 > len(payload):
                    return None
                name_len = int.from_bytes(payload[offset+3:offset+5], "big")
                name = payload[offset+5: offset+5+name_len]
                return name.decode("utf-8", errors="ignore")

            offset += ext_len

    except Exception:
        pass
    return None


# SNI → App type mapping
SNI_TO_APP = {
    "youtube":     "YOUTUBE",
    "googlevideo": "YOUTUBE",
    "facebook":    "FACEBOOK",
    "instagram":   "INSTAGRAM",
    "tiktok":      "TIKTOK",
    "twitter":     "TWITTER",
    "x.com":       "TWITTER",
    "netflix":     "NETFLIX",
    "twitch":      "STREAMING",
    "discord":     "VOIP",
    "whatsapp":    "VOIP",
    "zoom":        "VOIP",
    "github":      "DEVELOPER_TOOL",
    "openai":      "AI_SERVICE",
    "anthropic":   "AI_SERVICE",
    "torrent":     "P2P",
    "bittorrent":  "P2P",
    "google":      "GOOGLE",
    "amazon":      "CLOUD",
    "amazonaws":   "CLOUD",
    "cloudflare":  "CDN",
    "akamai":      "CDN",
}


def sni_to_app(sni: str) -> str:
    sni_lower = sni.lower()
    for pattern, app in SNI_TO_APP.items():
        if pattern in sni_lower:
            return app
    return "UNKNOWN"
