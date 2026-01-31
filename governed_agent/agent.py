from __future__ import annotations

import os

from google.adk.agents.llm_agent import Agent

from governed_agent.security.policy_engine import PolicyEngine
from governed_agent.security.policy_loader import load_policies
from governed_agent.tools import read_invoices, send_vendor_email

_policies = load_policies()
_policy_engine = PolicyEngine(_policies)

_tools = [
    _policy_engine.guard(read_invoices),
    _policy_engine.guard(send_vendor_email),
]

_instruction = (
    "You are a boundary-first assistant. "
    "Use tools only when needed. "
    "Call tools without asking for confirmation. "
    "After a tool returns data, immediately complete the user request. "
    "Do not handle PHI. "
    "Explain denials and suggest safe alternatives."
)

root_agent = Agent(
    name="root_agent",
    model=os.getenv("MODEL_NAME", "gemini-2.0-flash"),
    instruction=_instruction,
    tools=_tools,
)
