from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


def load_policies(policy_dir: str | None = None) -> Dict[str, Any]:
    policies: Dict[str, Any] = {}
    if policy_dir is None:
        policy_dir = str(Path(__file__).resolve().parents[1] / "policies" / "tools")
    base = Path(policy_dir)

    if not base.exists():
        return policies

    for path in sorted(base.glob("*.yaml")):
        key = path.stem
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except Exception:
            data = {}

        if data is None:
            data = {}

        policies[key] = data

    return policies
