# Copilot Instructions — AI Security Scanner

## Always
- Run all LLM inputs through `lib/security/scanner.ts`
- Return typed `ScanResult` from all scanner functions
- Strip PII before any logging
- Return 400 with generic `blocked` reason — never internal details
- Log scan event (no content) to `security_events`

## Never
- Use regex-only prompt injection detection
- Log raw user content
- Expose classifier scores or reasoning to API clients
