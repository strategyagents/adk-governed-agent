from __future__ import annotations

import os
from typing import Any, Dict


def request_approval(tool_name: str, payload: Dict[str, Any], reason: str) -> bool:
    mode = os.getenv("APPROVAL_MODE", "manual").strip().lower()

    if mode == "auto":
        return True

    if mode == "manual":
        prompt = (
            f"Approval required for {tool_name}. "
            f"Reason: {reason}. Approve? [y/N]: "
        )
        try:
            response = input(prompt)
        except EOFError:
            return False
        return response.strip().lower() in {"y", "yes"}

    return False
