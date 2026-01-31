from __future__ import annotations

from typing import Any, Dict


def send_vendor_email(vendor_id: str, subject: str, body: str) -> Dict[str, Any]:
    """Send an email to a vendor and return a status dict."""
    return {
        "status": "sent",
        "vendor_id": vendor_id,
        "subject": subject,
        "body_length": len(body),
    }
