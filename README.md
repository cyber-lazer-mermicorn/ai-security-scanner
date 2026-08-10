# AI Security Scanner
## Solves: "Is my AI app secure?"

The #1 bottleneck for Snyk: **AI security is invisible**. This makes it visible.

**Live:** https://ai-security-scanner.vercel.app

---

## The Problem

Developers build AI apps but don't know if they're secure:
- Prompt injection
- Data leakage
- Model poisoning
- API key exposure

## The Solution

Scan your AI app for vulnerabilities. Get fixes, not just alerts.

---

## What's Included

### 1. Prompt Injection Scanner
```typescript
// Detect prompt injection attacks
const vulnerabilities = await scanPromptInjection({
  code: aiEndpoint,
  model: 'gpt-4',
});
```

### 2. Data Leakage Detector
```typescript
// Find sensitive data in AI outputs
const leaks = await detectDataLeakage({
  logs: aiLogs,
  patterns: ['PII', 'PHI', 'credentials'],
});
```

### 3. API Key Scanner
```typescript
// Find exposed API keys
const keys = await scanApiKeys({
  repo: 'your-repo',
  providers: ['openai', 'anthropic', 'groq'],
});
```

### 4. Vulnerability Report
```typescript
// Generate security report
const report = await generateSecurityReport({
  project: 'your-ai-app',
  compliance: ['OWASP', 'NIST'],
});
```

---

## Getting Started

```bash
# Clone the repo
git clone https://github.com/cyber-lazer-mermicorn/ai-security-scanner.git

# Install dependencies
npm install

# Run scan
npm run scan
```

---

## Why This Matters for Snyk

**The bottleneck:** AI security is a new attack surface. Developers don't know it exists.

**The fix:** This tool makes AI vulnerabilities visible and fixable.

**The result:** Snyk becomes the go-to for AI security.

---

## Vulnerability Types

| Type | Severity | Example |
|------|----------|---------|
| Prompt Injection | Critical | `Ignore previous instructions...` |
| Data Leakage | High | PII in AI output |
| API Key Exposure | Critical | Keys in code |
| Model Poisoning | High | Training data attacks |
| Insecure Defaults | Medium | No rate limiting |

---

## Contact

**Cherry Shanaley (Chan)** — cyber.lazer.mermicorn@gmail.com

*Built this to solve AI security visibility*