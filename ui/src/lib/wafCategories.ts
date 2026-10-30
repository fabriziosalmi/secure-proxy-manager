/**
 * The WAF's category keys in words. The WAF counts a match under the
 * category of what matched (waf-go/main.go stats.record): a request rule
 * category (internal/engine/rules.go), a heuristic (internal/engine/
 * heuristics.go), a domain reputation check (DGA_DOMAIN, TYPOSQUATTING) or
 * the body size limit (BODY_OVERSIZE). Only the first kind is one of the
 * "request rule categories" that Protection coverage counts, so each label
 * says which kind it is.
 *
 * A key this file does not know (a new WAF category) is written in words
 * from its own name, never shown as the raw constant.
 */
export type WafCategoryKind = 'rule' | 'heuristic' | 'domain reputation' | 'size limit';

export interface WafCategoryLabel {
  label: string;
  kind: WafCategoryKind;
}

const LABELS: Record<string, string> = {
  SQL_INJECTION: 'SQL injection',
  XSS_ATTACKS: 'Cross-site scripting',
  XXE: 'XML external entities',
  SSRF: 'Server-side request forgery',
  COMMAND_INJECTION: 'Command injection',
  DIRECTORY_TRAVERSAL: 'Directory traversal',
  PATH_MANIPULATION: 'Path manipulation',
  SENSITIVE_FILES: 'Sensitive files',
  JAVA_DESER: 'Java deserialisation',
  PROTOTYPE_POLLUTION: 'Prototype pollution',
  TEMPLATE_INJECTION: 'Server-side template injection',
  UNICODE_OBFUSCATION: 'Unicode obfuscation',
  PROTOCOL_ANOMALY: 'Protocol anomaly',
  POST_EXPLOIT: 'Post-exploitation tools',
  LOG4SHELL: 'Log4Shell',
  WEBSHELL_C2: 'Web shells and command and control',
  RANSOMWARE: 'Ransomware',
  CRYPTO_TUNNEL: 'Crypto mining and tunnels',
  DATA_EXFIL: 'Data exfiltration',
  DATA_LEAK_PREVENTION: 'Data leak prevention',
  FINANCIAL_DATA: 'Financial data',
  CLOUD_SECRETS: 'Cloud secrets',
  CUSTOM_USER_RULES: 'Custom patterns',
  RESPONSE_XSS: 'Cross-site scripting in responses',
  RESPONSE_SECRET_LEAK: 'Secrets in responses',
  HEURISTIC_BEACONING: 'Beaconing (regular call-backs)',
  HEURISTIC_ENTROPY: 'High-entropy payload',
  HEURISTIC_GHOSTING: 'Another protocol inside HTTP',
  HEURISTIC_PII_LEAK: 'Personal data leak',
  HEURISTIC_SEQUENCE: 'Impossible request sequence',
  HEURISTIC_SHARDING: 'Many destinations at once',
  DGA_DOMAIN: 'Generated domain name (DGA)',
  TYPOSQUATTING: 'Typosquatted domain',
  BODY_OVERSIZE: 'Body over the inspection limit',
  // The OWASP Core Rule Set's families (waf-go/internal/crs/crs.go, families).
  CRS: 'Core Rule Set',
  CRS_METHOD: 'Request method (Core Rule Set)',
  CRS_SCANNER: 'Scanner (Core Rule Set)',
  CRS_PROTOCOL: 'Protocol enforcement (Core Rule Set)',
  CRS_PROTOCOL_ATTACK: 'Protocol attack (Core Rule Set)',
  CRS_MULTIPART: 'Multipart attack (Core Rule Set)',
  CRS_LFI: 'Local file inclusion (Core Rule Set)',
  CRS_RFI: 'Remote file inclusion (Core Rule Set)',
  CRS_RCE: 'Remote command execution (Core Rule Set)',
  CRS_PHP: 'PHP injection (Core Rule Set)',
  CRS_GENERIC: 'Generic attack (Core Rule Set)',
  CRS_XSS: 'Cross-site scripting (Core Rule Set)',
  CRS_SQLI: 'SQL injection (Core Rule Set)',
  CRS_SESSION: 'Session fixation (Core Rule Set)',
  CRS_JAVA: 'Java attack (Core Rule Set)',
};

const DOMAIN_REPUTATION = new Set(['DGA_DOMAIN', 'TYPOSQUATTING']);
const ACRONYMS = new Set(['SQL', 'XSS', 'XXE', 'SSRF', 'PII', 'DGA', 'DLP', 'C2', 'RCE', 'LFI', 'RFI', 'SSTI', 'API', 'JWT', 'HTTP']);

function kindOf(key: string): WafCategoryKind {
  if (key.startsWith('HEURISTIC_')) return 'heuristic';
  if (DOMAIN_REPUTATION.has(key)) return 'domain reputation';
  if (key === 'BODY_OVERSIZE') return 'size limit';
  return 'rule';
}

/** "XSS_EXTRA_CHECK" -> "XSS extra check": words in lower case, acronyms kept, the first capitalised. */
function fromKey(key: string): string {
  const words = key.split('_').filter(Boolean).map((w) => (ACRONYMS.has(w.toUpperCase()) ? w.toUpperCase() : w.toLowerCase()));
  if (words.length === 0) return key;
  words[0] = words[0].charAt(0).toUpperCase() + words[0].slice(1);
  return words.join(' ');
}

/** The words and the kind for a WAF category key. */
export function wafCategoryLabel(key: string): WafCategoryLabel {
  return { label: LABELS[key] ?? fromKey(key), kind: kindOf(key) };
}
