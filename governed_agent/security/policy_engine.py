from __future__ import annotations

import functools
import inspect
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


class PolicyDenied(Exception):
    pass


class PolicyEngine:
    REQUIRED_FIELDS = {"tool", "summary", "inputs", "scopes", "guardrails", "approvals"}

    def __init__(
        self,
        policies: Optional[Dict[str, Dict[str, Any]]],
        approval_handler: Optional[Callable[..., bool]] = None,
    ) -> None:
        self._policies = policies if isinstance(policies, dict) else {}
        if approval_handler is None:
            approval_handler = self._load_default_approval_handler()
        self._approval_handler = approval_handler

    def guard(self, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(tool_fn)
        tool_name = tool_fn.__name__

        @functools.wraps(tool_fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            payload = self._bind_payload(sig, args, kwargs)
            policy = self._get_policy(tool_name, payload)
            self._validate_policy(policy, tool_name, payload)
            max_rows = self._apply_guardrails(policy, tool_name, payload)

            approval_required, approval_reason = self._requires_approval(
                policy, tool_name, payload
            )
            if approval_required:
                self._log_event(
                    tool_name=tool_name,
                    allowed=None,
                    approval_required=True,
                    approval_status="required",
                    payload=payload,
                    reason=approval_reason,
                )
                approved = self._request_approval(tool_name, payload, approval_reason)
                if not approved:
                    self._deny(
                        tool_name,
                        payload,
                        "Approval rejected",
                        approval_required=True,
                        approval_status="rejected",
                    )
                self._log_event(
                    tool_name=tool_name,
                    allowed=None,
                    approval_required=True,
                    approval_status="approved",
                    payload=payload,
                    reason=approval_reason,
                )

            result = tool_fn(*args, **kwargs)
            result = self._apply_post_guardrails(result, max_rows)
            self._log_event(
                tool_name=tool_name,
                allowed=True,
                approval_required=approval_required,
                approval_status="approved" if approval_required else "not_required",
                payload=payload,
            )
            return result

        wrapped.__signature__ = sig
        return wrapped

    def _bind_payload(
        self,
        sig: inspect.Signature,
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)

    def _get_policy(self, tool_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        policy = self._policies.get(tool_name)
        if policy is None:
            self._deny(tool_name, payload, f"Missing policy for tool '{tool_name}'")
        return policy

    def _validate_policy(
        self,
        policy: Dict[str, Any],
        tool_name: str,
        payload: Dict[str, Any],
    ) -> None:
        if not isinstance(policy, dict):
            self._deny(tool_name, payload, "Policy is not a mapping")

        missing = [field for field in self.REQUIRED_FIELDS if field not in policy]
        if missing:
            self._deny(tool_name, payload, f"Policy missing fields: {', '.join(missing)}")

        if policy.get("tool") != tool_name:
            self._deny(
                tool_name,
                payload,
                f"Policy tool name mismatch: expected '{tool_name}'",
            )

        if not isinstance(policy.get("summary"), str):
            self._deny(tool_name, payload, "Policy summary must be a string")
        if not isinstance(policy.get("inputs"), list):
            self._deny(tool_name, payload, "Policy inputs must be a list")
        if not isinstance(policy.get("guardrails"), list):
            self._deny(tool_name, payload, "Policy guardrails must be a list")
        if not isinstance(policy.get("approvals"), list):
            self._deny(tool_name, payload, "Policy approvals must be a list")

        scopes = policy.get("scopes")
        if not isinstance(scopes, dict):
            self._deny(tool_name, payload, "Policy scopes must be a mapping")
        if "read" not in scopes or "write" not in scopes:
            self._deny(tool_name, payload, "Policy scopes must include read and write")
        if not isinstance(scopes.get("read"), list) or not isinstance(scopes.get("write"), list):
            self._deny(tool_name, payload, "Policy scopes read/write must be lists")

    def _apply_guardrails(
        self,
        policy: Dict[str, Any],
        tool_name: str,
        payload: Dict[str, Any],
    ) -> Optional[int]:
        guardrails = policy.get("guardrails", [])
        max_rows: Optional[int] = None

        for rule in guardrails:
            if not isinstance(rule, dict):
                self._deny(tool_name, payload, "Guardrail entry must be a mapping")

            if "block_keywords" in rule:
                keywords = rule["block_keywords"]
                if not isinstance(keywords, list):
                    self._deny(tool_name, payload, "block_keywords must be a list")
                body = payload.get("body", "")
                body_text = "" if body is None else str(body)
                for kw in keywords:
                    if not isinstance(kw, str):
                        self._deny(tool_name, payload, "block_keywords entries must be strings")
                    if kw and kw.lower() in body_text.lower():
                        self._deny(tool_name, payload, "Blocked keyword detected in body")

            if "max_recipients" in rule:
                max_recipients = rule["max_recipients"]
                if not isinstance(max_recipients, int) or max_recipients < 0:
                    self._deny(tool_name, payload, "max_recipients must be a non-negative int")
                recipients = payload.get("recipients")
                if isinstance(recipients, list) and len(recipients) > max_recipients:
                    self._deny(tool_name, payload, "Recipient count exceeds max_recipients")

            if "domain_allowlist" in rule:
                allowlist = rule["domain_allowlist"]
                if not isinstance(allowlist, list):
                    self._deny(tool_name, payload, "domain_allowlist must be a list")
                allowset = {str(item).lower() for item in allowlist}
                self._enforce_domain_allowlist(tool_name, payload, allowset)

            if "max_rows" in rule:
                candidate = rule["max_rows"]
                if not isinstance(candidate, int) or candidate < 0:
                    self._deny(tool_name, payload, "max_rows must be a non-negative int")
                max_rows = candidate if max_rows is None else min(max_rows, candidate)

        return max_rows

    def _enforce_domain_allowlist(
        self,
        tool_name: str,
        payload: Dict[str, Any],
        allowset: Iterable[str],
    ) -> None:
        allowset = {domain for domain in allowset if domain}
        if not allowset:
            return

        def check_email(value: str) -> None:
            if "@" not in value:
                self._deny(tool_name, payload, "Email missing domain for allowlist check")
            domain = value.rsplit("@", 1)[-1].lower()
            if domain not in allowset:
                self._deny(tool_name, payload, "Recipient domain not in allowlist")

        for key in ("recipient_email", "to"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                check_email(value)

        recipients = payload.get("recipients")
        if isinstance(recipients, list):
            for item in recipients:
                if isinstance(item, str) and item:
                    check_email(item)

    def _requires_approval(
        self, policy: Dict[str, Any], tool_name: str, payload: Dict[str, Any]
    ) -> Tuple[bool, str]:
        approvals = policy.get("approvals", [])
        for condition in approvals:
            if not isinstance(condition, str):
                self._deny(tool_name, payload, "Approval condition must be a string")
            try:
                if self._eval_condition(condition, payload):
                    return True, condition
            except ValueError:
                self._deny(tool_name, payload, "Invalid approval condition syntax")
        return False, ""

    def _eval_condition(self, condition: str, payload: Dict[str, Any]) -> bool:
        clauses = re.split(r"\s+OR\s+", condition.strip(), flags=re.IGNORECASE)
        if not clauses:
            raise ValueError("No clauses")

        for clause in clauses:
            clause = clause.strip()
            if not clause:
                raise ValueError("Empty clause")
            match = re.fullmatch(
                r"contains\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*'([^']*)'\s*\)",
                clause,
            )
            if not match:
                match = re.fullmatch(
                    r'contains\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*"([^"]*)"\s*\)',
                    clause,
                )
            if not match:
                raise ValueError("Unsupported clause")

            field, text = match.group(1), match.group(2)
            value = payload.get(field)
            haystack = "" if value is None else str(value)
            if text.lower() in haystack.lower():
                return True

        return False

    def _request_approval(
        self, tool_name: str, payload: Dict[str, Any], reason: str
    ) -> bool:
        if self._approval_handler is None:
            self._deny(
                tool_name,
                payload,
                "Approval handler not configured",
                approval_required=True,
                approval_status="rejected",
            )
        try:
            return bool(
                self._approval_handler(tool_name=tool_name, payload=payload, reason=reason)
            )
        except TypeError:
            return bool(self._approval_handler(tool_name, payload, reason))

    def _apply_post_guardrails(self, result: Any, max_rows: Optional[int]) -> Any:
        if max_rows is None:
            return result
        if isinstance(result, list):
            return result[:max_rows]
        return result

    def _load_default_approval_handler(self) -> Optional[Callable[..., bool]]:
        try:
            from .approvals import request_approval  # type: ignore

            return request_approval
        except Exception:
            return None

    def _log_event(
        self,
        tool_name: str,
        allowed: Optional[bool],
        approval_required: Optional[bool],
        approval_status: Optional[str],
        payload: Dict[str, Any],
        reason: Optional[str] = None,
    ) -> None:
        event: Dict[str, Any] = {"tool_name": tool_name}
        if allowed is not None:
            event["allowed"] = allowed
        if approval_required is not None:
            event["approval_required"] = approval_required
        if approval_status is not None:
            event["approval_status"] = approval_status
        if reason:
            event["reason"] = reason
        event["payload"] = self._sanitize_payload(payload)
        print(json.dumps(event, sort_keys=True))

    def _sanitize_payload(self, payload: Dict[str, Any]) -> Dict[str, str]:
        summary: Dict[str, str] = {}
        for key, value in payload.items():
            if isinstance(value, str):
                summary[key] = f"<str:{len(value)}>"
            elif isinstance(value, list):
                summary[key] = f"<list:{len(value)}>"
            elif isinstance(value, dict):
                summary[key] = f"<dict:{len(value)}>"
            elif value is None:
                summary[key] = "<none>"
            else:
                summary[key] = f"<{type(value).__name__}>"
        return summary

    def _deny(
        self,
        tool_name: str,
        payload: Dict[str, Any],
        reason: str,
        approval_required: Optional[bool] = None,
        approval_status: Optional[str] = None,
    ) -> None:
        self._log_event(
            tool_name=tool_name,
            allowed=False,
            approval_required=approval_required,
            approval_status=approval_status,
            payload=payload,
            reason=reason,
        )
        raise PolicyDenied(reason)
