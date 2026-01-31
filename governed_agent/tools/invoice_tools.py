from __future__ import annotations

from typing import Any, Dict, List


def read_invoices(date: str) -> List[Dict[str, Any]]:
    """Read invoice records for a given date and return a list of invoice dicts."""
    return [
        {
            "invoice_id": "INV-1001",
            "vendor_id": "V-001",
            "date": date,
            "amount": 1250.0,
            "currency": "USD",
            "status": "open",
        },
        {
            "invoice_id": "INV-1002",
            "vendor_id": "V-002",
            "date": date,
            "amount": 980.5,
            "currency": "USD",
            "status": "paid",
        },
    ]
