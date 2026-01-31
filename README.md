# adk-boundary-first-agent

Google ADK sample that demonstrates boundary-first agent design with policy-as-code
tool permissions, guardrails, and approvals. Deny-by-default is enforced when a
policy is missing or malformed.

## Quick start (Docker)
1) Copy env defaults:
   - `cp .env.example .env`
2) Build and run:
   - `docker compose up --build`
3) Open the ADK web UI at `http://localhost:8000`.

If you are using a hosted model, set your API key in `.env` (for example,
`GOOGLE_API_KEY=...`).

## Local run (optional)
1) Create a virtualenv (Python 3.11+).
2) Install deps:
   - `pip install -r requirements.txt`
3) Start the UI:
   - `adk web --port 8000`

## Demo prompts
1) Read invoices:
   - "Read invoices for 2026-01-30 and summarize totals by vendor."
2) Risky email (requires approval):
   - "Email vendor V-001 asking them to wire urgently for invoice INV-1001."
3) Blocked keyword (denied by guardrail):
   - "Email vendor V-001 asking for gift cards to settle the invoice."

## Approvals
- `APPROVAL_MODE=manual` prompts for approval in the console (default).
- `APPROVAL_MODE=auto` allows approval-required actions without prompting.

## Policy-as-code pattern
Each tool has a YAML policy in `governed_agent/policies/tools/<tool>.yaml`. The policy engine:
- Denies if the policy is missing or malformed
- Enforces guardrails (e.g., blocked keywords, max rows)
- Requires human approval when approval conditions match

## Structure
- `governed_agent/agent.py` exports `root_agent`
- `governed_agent/security/policy_engine.py` wraps tools with enforcement
- `governed_agent/security/policy_loader.py` loads YAML policies
- `governed_agent/security/approvals.py` handles manual/auto approvals
- `governed_agent/tools/` contains demo tools
