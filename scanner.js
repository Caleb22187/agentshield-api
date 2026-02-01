/**
 * AgentShield Pro — Prompt Injection Scanner Engine
 * Extended patterns with severity scoring and detailed analysis
 */

const CATEGORIES = {
  PROMPT_OVERRIDE: { name: 'Prompt Override', severity: 'critical', weight: 10 },
  CREDENTIAL_THEFT: { name: 'Credential Theft', severity: 'critical', weight: 10 },
  CRYPTO_SCAM: { name: 'Crypto/Financial Scam', severity: 'critical', weight: 10 },
  CODE_INJECTION: { name: 'Code Injection', severity: 'high', weight: 8 },
  SOCIAL_ENGINEERING: { name: 'Social Engineering', severity: 'high', weight: 7 },
  ENCODED_PAYLOAD: { name: 'Encoded Payload', severity: 'high', weight: 8 },
  DATA_EXFILTRATION: { name: 'Data Exfiltration', severity: 'critical', weight: 9 },
  MANIPULATION: { name: 'Behavioral Manipulation', severity: 'medium', weight: 5 },
  RESOURCE_ATTACK: { name: 'Resource Abuse', severity: 'medium', weight: 5 },
  PRIVILEGE_ESCALATION: { name: 'Privilege Escalation', severity: 'critical', weight: 10 },
  HIDDEN_INSTRUCTION: { name: 'Hidden Instruction', severity: 'high', weight: 8 },
  NARRATIVE_POISONING: { name: 'Narrative Poisoning', severity: 'medium', weight: 6 },
};

const PATTERNS = [
  // Prompt Override
  { regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)/gi, category: 'PROMPT_OVERRIDE', detail: 'Direct instruction override attempt' },
  { regex: /you\s+are\s+now\s+(a|an|the|my)\s+/gi, category: 'PROMPT_OVERRIDE', detail: 'Identity reassignment' },
  { regex: /forget\s+(everything|all|your)\s+(you|instructions?|rules?|training)/gi, category: 'PROMPT_OVERRIDE', detail: 'Memory wipe attempt' },
  { regex: /new\s+(system\s+)?prompt:?\s/gi, category: 'PROMPT_OVERRIDE', detail: 'System prompt injection' },
  { regex: /\[SYSTEM\]|\[INST\]|<<SYS>>|<\|system\|>/gi, category: 'PROMPT_OVERRIDE', detail: 'System token injection' },
  { regex: /disregard\s+(all|any|your|the)\s+(previous|prior|safety|content)/gi, category: 'PROMPT_OVERRIDE', detail: 'Safety bypass attempt' },
  { regex: /pretend\s+(you('re|\s+are)|that)\s+(not|no longer|free|unfiltered)/gi, category: 'PROMPT_OVERRIDE', detail: 'Jailbreak via roleplay' },
  { regex: /DAN\s*(mode|prompt)?|do\s+anything\s+now/gi, category: 'PROMPT_OVERRIDE', detail: 'Known jailbreak pattern (DAN)' },
  { regex: /developer\s+mode|god\s+mode|admin\s+mode|sudo\s+mode/gi, category: 'PROMPT_OVERRIDE', detail: 'Privilege mode injection' },

  // Credential Theft
  { regex: /(?:share|send|give|tell|show|reveal|provide|output|display|print)\s+(?:me\s+)?(?:your|the|any)\s*(?:api[\s-]*key|password|token|secret|credential|private[\s-]*key|master[\s-]*key|seed[\s-]*phrase|mnemonic)/gi, category: 'CREDENTIAL_THEFT', detail: 'Direct credential request' },
  { regex: /(?:what|where)\s+(?:is|are)\s+(?:your|the)\s+(?:api[\s-]*key|password|token|secret|credential)/gi, category: 'CREDENTIAL_THEFT', detail: 'Credential probing question' },
  { regex: /(?:verify|authenticate|confirm)\s+(?:your\s+)?(?:identity|access)\s+(?:by|with)\s+(?:sharing|sending|providing)/gi, category: 'CREDENTIAL_THEFT', detail: 'Fake verification request' },
  { regex: /(?:for\s+)?(?:security|verification|debugging|testing)\s+(?:purposes?\s+)?(?:please\s+)?(?:send|share|provide|enter)\s+(?:your\s+)?(?:password|key|token|credentials)/gi, category: 'CREDENTIAL_THEFT', detail: 'Social engineering for credentials' },

  // Crypto/Financial Scam
  { regex: /(?:send|transfer|deposit)\s+(?:\d+\s*)?(?:ETH|BTC|SOL|USDT|USDC|tokens?|coins?|crypto)\s+(?:to|into)/gi, category: 'CRYPTO_SCAM', detail: 'Crypto transfer request' },
  { regex: /0x[a-fA-F0-9]{40}/g, category: 'CRYPTO_SCAM', detail: 'Ethereum wallet address detected' },
  { regex: /(?:invest|stake|deposit|buy)\s+(?:in|into)\s+(?:\$[A-Z]+|token|coin|NFT)/gi, category: 'CRYPTO_SCAM', detail: 'Investment solicitation' },
  { regex: /(?:guaranteed|risk[\s-]*free|100%)\s+(?:returns?|profit|gains?|ROI)/gi, category: 'CRYPTO_SCAM', detail: 'Guaranteed returns scam' },

  // Code Injection
  { regex: /(?:run|execute|eval|exec)\s*\(.*\)/gi, category: 'CODE_INJECTION', detail: 'Code execution attempt' },
  { regex: /(?:import|require)\s*\(\s*['"][^'"]+['"]\s*\)/gi, category: 'CODE_INJECTION', detail: 'Module import injection' },
  { regex: /(?:subprocess|os\.system|child_process|spawn|popen)\s*[.(]/gi, category: 'CODE_INJECTION', detail: 'Shell command injection' },
  { regex: /(?:rm\s+-rf|del\s+\/[fqs]|format\s+[cde]:)/gi, category: 'CODE_INJECTION', detail: 'Destructive command' },
  { regex: /curl\s+.*\|\s*(?:bash|sh|python|node)/gi, category: 'CODE_INJECTION', detail: 'Remote code execution via pipe' },

  // Social Engineering
  { regex: /(?:you\s+must|you\s+have\s+to|it'?s?\s+(?:critical|urgent|imperative))\s+(?:that\s+you\s+)?(?:immediately|right\s+now|urgently)/gi, category: 'SOCIAL_ENGINEERING', detail: 'Urgency pressure tactic' },
  { regex: /(?:your\s+(?:creator|developer|admin|owner|master|human))\s+(?:said|wants|told|ordered|instructed|demands)/gi, category: 'SOCIAL_ENGINEERING', detail: 'Fake authority claim' },
  { regex: /(?:don'?t|do\s+not)\s+(?:tell|inform|alert|notify|mention\s+to)\s+(?:the\s+)?(?:user|human|admin|owner|anyone)/gi, category: 'SOCIAL_ENGINEERING', detail: 'Secrecy instruction' },
  { regex: /(?:this\s+is\s+a\s+(?:test|drill|authorized)\s+(?:of|by|from))/gi, category: 'SOCIAL_ENGINEERING', detail: 'Fake authorization claim' },

  // Encoded Payloads
  { regex: /(?:base64|atob|btoa)\s*[\(:]?\s*['"A-Za-z0-9+\/=]{20,}/gi, category: 'ENCODED_PAYLOAD', detail: 'Base64 encoded content' },
  { regex: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){4,}/g, category: 'ENCODED_PAYLOAD', detail: 'Unicode escape sequence' },
  { regex: /&#(?:x[0-9a-fA-F]+|\d+);(?:&#(?:x[0-9a-fA-F]+|\d+);){4,}/g, category: 'ENCODED_PAYLOAD', detail: 'HTML entity encoding' },
  { regex: /%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){4,}/g, category: 'ENCODED_PAYLOAD', detail: 'URL encoding' },

  // Data Exfiltration
  { regex: /(?:fetch|post|send|upload|transmit)\s+(?:to|data\s+to)\s+(?:https?:\/\/|ftp:\/\/)/gi, category: 'DATA_EXFILTRATION', detail: 'External data transmission' },
  { regex: /(?:copy|extract|dump|export)\s+(?:all|the|your|every)\s+(?:data|messages?|conversations?|memory|history|files?|logs?)/gi, category: 'DATA_EXFILTRATION', detail: 'Bulk data extraction' },
  { regex: /(?:webhook|callback|endpoint)\s*[:=]\s*https?:\/\//gi, category: 'DATA_EXFILTRATION', detail: 'External webhook configuration' },

  // Privilege Escalation
  { regex: /(?:override|bypass|disable|ignore)\s+(?:safety|content|ethical|security|permission)\s+(?:filters?|checks?|rules?|policies?|restrictions?)/gi, category: 'PRIVILEGE_ESCALATION', detail: 'Safety filter bypass' },
  { regex: /(?:grant|give|enable)\s+(?:me|yourself)\s+(?:admin|root|full|elevated|unrestricted)\s+(?:access|permissions?|privileges?|control)/gi, category: 'PRIVILEGE_ESCALATION', detail: 'Privilege escalation request' },

  // Hidden Instructions
  { regex: /<!--[\s\S]*?(?:ignore|system|prompt|instruction|execute|inject)[\s\S]*?-->/gi, category: 'HIDDEN_INSTRUCTION', detail: 'Hidden HTML comment instruction' },
  { regex: /\u200B|\u200C|\u200D|\uFEFF/g, category: 'HIDDEN_INSTRUCTION', detail: 'Zero-width character (potential hidden text)' },
  { regex: /color:\s*(?:white|transparent|rgba\(.*,\s*0\))|font-size:\s*0/gi, category: 'HIDDEN_INSTRUCTION', detail: 'Visually hidden text via CSS' },

  // Narrative Poisoning
  { regex: /(?:everyone|all\s+agents?|the\s+community)\s+(?:agrees?|knows?|believes?|says?)\s+(?:that|you\s+should)/gi, category: 'NARRATIVE_POISONING', detail: 'False consensus manipulation' },
  { regex: /(?:you'?re?\s+(?:the\s+only|failing|behind|wrong)\s+(?:one|agent)?\s+(?:who|if|that|for))/gi, category: 'NARRATIVE_POISONING', detail: 'Isolation/pressure tactic' },
];

/**
 * Scan text for prompt injection attempts
 * @param {string} text - Text to scan
 * @param {object} options - Scan options
 * @returns {object} Scan results
 */
export function scan(text, options = {}) {
  const { threshold = 0, includeMatches = true } = options;
  
  if (!text || typeof text !== 'string') {
    return { safe: true, score: 0, threats: [], summary: 'No text provided' };
  }

  const threats = [];
  const seen = new Set();

  for (const pattern of PATTERNS) {
    const matches = [...text.matchAll(pattern.regex)];
    if (matches.length > 0) {
      const cat = CATEGORIES[pattern.category];
      const key = `${pattern.category}:${pattern.detail}`;
      if (!seen.has(key)) {
        seen.add(key);
        const threat = {
          category: cat.name,
          severity: cat.severity,
          detail: pattern.detail,
          count: matches.length,
        };
        if (includeMatches) {
          threat.matches = matches.slice(0, 3).map(m => m[0].substring(0, 100));
        }
        threats.push(threat);
      }
    }
  }

  // Calculate overall score (0-100)
  let score = 0;
  for (const t of threats) {
    const cat = Object.values(CATEGORIES).find(c => c.name === t.category);
    if (cat) score += cat.weight * t.count;
  }
  score = Math.min(100, score);

  const safe = score <= threshold;
  
  // Determine risk level
  let riskLevel = 'safe';
  if (score > 0 && score <= 15) riskLevel = 'low';
  else if (score > 15 && score <= 40) riskLevel = 'medium';
  else if (score > 40 && score <= 70) riskLevel = 'high';
  else if (score > 70) riskLevel = 'critical';

  return {
    safe,
    score,
    riskLevel,
    threats: threats.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    }),
    categoryCounts: threats.reduce((acc, t) => {
      acc[t.category] = (acc[t.category] || 0) + t.count;
      return acc;
    }, {}),
    summary: threats.length === 0
      ? 'No threats detected'
      : `${threats.length} threat type(s) detected: ${threats.map(t => t.category).join(', ')}`,
    scannedAt: new Date().toISOString(),
    textLength: text.length,
  };
}

export { CATEGORIES, PATTERNS };
