# AI Security Scanner — Agent Doctrine

## What this repo is
AI-powered security scanning: prompt injection detection, secret scanning, PII detection, and LLM output sanitization.
By Cherry Shanaley (Chan), AI Solutions Engineer.

## Tech stack
- TypeScript strict, Next.js 15, OpenAI moderation + custom classifiers

## Coding rules
- Every LLM input MUST pass through `lib/security/scanner.ts` before forwarding
- Prompt injection detection uses a dedicated classifier — not just regex
- PII detection strips before logging — never log raw user input
- Scan results are typed `ScanResult` with `{ safe: boolean, flags: Flag[], severity: 'low'|'medium'|'high'|'critical' }`
- Blocked requests return 400 with `{ error: 'blocked', reason: string }` — never the scanner's internal reasoning
- All scan results logged (without content) to `security_events` table

## Commands
```bash
npm install && npm run dev
npm run test
npm run scan -- --input 'test prompt'
```

## Do not
- Log raw user input
- Expose scanner reasoning to clients
- Use regex alone for injection detection
- Skip scanning any LLM-bound input
