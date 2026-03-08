"""
HTTP Inspector
Extracts the Host header from plaintext HTTP request payloads.
"""

from typing import Optional

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ")


def extract_host(payload: bytes) -> Optional[str]:
    """Return the value of the HTTP Host header, or None."""
    try:
        if not any(payload.startswith(m) for m in HTTP_METHODS):
            return None
        for line in payload.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                return line.split(b":", 1)[1].strip().decode("utf-8", errors="ignore")
    except Exception:
        pass
    return None
