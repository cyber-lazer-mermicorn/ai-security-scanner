import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export interface Vulnerability {
  type: 'prompt_injection' | 'data_leakage' | 'api_key_exposure' | 'insecure_defaults';
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line: number;
  description: string;
  fix: string;
}

// Scan for prompt injection vulnerabilities
export async function scanPromptInjection(code: string): Promise<Vulnerability[]> {
  const response = await openai.chat.completions.create({
    model: 'gpt-4-turbo-preview',
    messages: [
      {
        role: 'system',
        content: `You are a security expert. Scan code for prompt injection vulnerabilities.
        Return JSON array of vulnerabilities with: type, severity, file, line, description, fix.`,
      },
      { role: 'user', content: `Scan this code:\n${code}` },
    ],
    response_format: { type: 'json_object' },
  });

  return JSON.parse(response.choices[0].message.content || '[]');
}

// Scan for API key exposure
export async function scanApiKeys(code: string): Promise<Vulnerability[]> {
  const patterns = [
    { regex: /sk-[a-zA-Z0-9]{48}/g, provider: 'OpenAI' },
    { regex: /gsk_[a-zA-Z0-9]{48}/g, provider: 'Groq' },
    { regex: /sk-ant-[a-zA-Z0-9]{48}/g, provider: 'Anthropic' },
    { regex: /AKIA[A-Z0-9]{16}/g, provider: 'AWS' },
  ];

  const vulnerabilities: Vulnerability[] = [];

  for (const pattern of patterns) {
    const matches = code.match(pattern.regex);
    if (matches) {
      vulnerabilities.push({
        type: 'api_key_exposure',
        severity: 'critical',
        file: 'scanned-file',
        line: 0,
        description: `Exposed ${pattern.provider} API key detected`,
        fix: 'Move API keys to environment variables',
      });
    }
  }

  return vulnerabilities;
}

// Scan for data leakage
export async function scanDataLeakage(code: string): Promise<Vulnerability[]> {
  const piiPatterns = [
    { regex: /\b\d{3}-\d{2}-\d{4}\b/g, type: 'SSN' },
    { regex: /\b\d{16}\b/g, type: 'Credit Card' },
    { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: 'Email' },
  ];

  const vulnerabilities: Vulnerability[] = [];

  for (const pattern of piiPatterns) {
    const matches = code.match(pattern.regex);
    if (matches) {
      vulnerabilities.push({
        type: 'data_leakage',
        severity: 'high',
        file: 'scanned-file',
        line: 0,
        description: `Potential ${pattern.type} in code output`,
        fix: 'Sanitize AI outputs to remove PII',
      });
    }
  }

  return vulnerabilities;
}

// Full security scan
export async function fullSecurityScan(code: string) {
  const [promptVulns, apiKeyVulns, dataVulns] = await Promise.all([
    scanPromptInjection(code),
    scanApiKeys(code),
    scanDataLeakage(code),
  ]);

  const allVulns = [...promptVulns, ...apiKeyVulns, ...dataVulns];

  return {
    vulnerabilities: allVulns,
    summary: {
      total: allVulns.length,
      critical: allVulns.filter(v => v.severity === 'critical').length,
      high: allVulns.filter(v => v.severity === 'high').length,
      medium: allVulns.filter(v => v.severity === 'medium').length,
      low: allVulns.filter(v => v.severity === 'low').length,
    },
    score: Math.max(0, 100 - allVulns.length * 10),
  };
}