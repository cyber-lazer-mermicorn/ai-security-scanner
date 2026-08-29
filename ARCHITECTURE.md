# Architecture

## Scanner pipeline
Input → PII strip → moderation API → injection classifier → custom rules → `ScanResult` → allow/block.

## Scan flags

| Flag | Description | Severity |
|---|---|---|
| `prompt_injection` | Attempt to override system prompt | critical |
| `jailbreak` | Attempt to bypass safety | high |
| `pii_detected` | Personal data in input | medium |
| `toxic_content` | Harmful/offensive content | high |
| `secret_exposed` | API key or credential in input | critical |

## Response contract
Blocked: `{ error: 'blocked', reason: 'policy_violation' }` (never scanner internals).
Allowed: pass through to LLM.
