import path from 'node:path';

const DEFAULT_BLOCKED_BASENAMES = new Set([
  '.env',
  '.npmrc',
  '.pypirc',
  '.netrc',
  'id_rsa',
  'id_ed25519',
]);

const DEFAULT_ALLOWED_BASH_PREFIXES = [
  'npm ',
  'pnpm ',
  'yarn ',
  'bun ',
  'npx ',
  'uv ',
  'poetry ',
  'pip ',
  'python ',
  'python3 ',
  'go ',
  'cargo ',
  'tsc',
  'git status',
  'git diff',
  'ls',
];

const DANGEROUS_BASH_PATTERNS: RegExp[] = [
  /\brm\s+-rf\s+\//,
  /\bcurl\b.*\|\s*(sh|bash)/i,
  /\bwget\b.*\|\s*(sh|bash)/i,
  /\bcat\b[^\n]*\.env\b/i,
  /\bprintenv\b/i,
  /\benv\b\s*($|\||;)/,
  /\bgit\s+push\b/,
];

const SECRET_OUTPUT_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: 'anthropic-key', regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'openrouter-key', regex: /\bsk-or-v1-[A-Za-z0-9]{20,}\b/g },
  { name: 'openai-key', regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'aws-access-key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'github-token', regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  {
    name: 'private-key',
    regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
  },
];

export interface SecurityPolicy {
  projectDir: string;
  allowBash: boolean;
  extraBlockedPaths?: string[];
  allowedBashPrefixes?: string[];
}

export function isPathBlockedForModelRead(
  targetPath: string,
  policy: SecurityPolicy,
): string | null {
  const resolved = path.resolve(policy.projectDir, targetPath);
  const rel = path.relative(policy.projectDir, resolved);

  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return `Path "${targetPath}" escapes the project directory`;
  }

  const base = path.basename(resolved);
  if (
    base.startsWith('.env') &&
    base !== '.env.example' &&
    base !== '.env.sample' &&
    base !== '.env.template'
  ) {
    return `Reading "${base}" is blocked to keep secrets off the LLM`;
  }

  if (DEFAULT_BLOCKED_BASENAMES.has(base)) {
    return `Reading "${base}" is blocked by Collision security policy`;
  }

  for (const extra of policy.extraBlockedPaths ?? []) {
    if (rel === extra || rel.startsWith(`${extra}${path.sep}`)) {
      return `Reading "${rel}" is blocked by vendor security policy`;
    }
  }

  return null;
}

export function checkBashCommand(
  command: string,
  policy: SecurityPolicy,
): string | null {
  if (!policy.allowBash) {
    return 'Bash execution is disabled by policy';
  }

  const trimmed = command.trim();
  if (!trimmed) return 'Empty command';

  for (const pattern of DANGEROUS_BASH_PATTERNS) {
    if (pattern.test(trimmed)) {
      return `Command blocked by safety rule: ${pattern.source}`;
    }
  }

  const prefixes = [
    ...DEFAULT_ALLOWED_BASH_PREFIXES,
    ...(policy.allowedBashPrefixes ?? []),
  ];

  const allowed = prefixes.some(
    (prefix) => trimmed === prefix.trim() || trimmed.startsWith(prefix),
  );
  if (!allowed) {
    return `Command "${trimmed.split(/\s+/)[0]}" is not in the bash allowlist`;
  }

  return null;
}

export function redactSecretsInOutput(text: string): {
  sanitized: string;
  findings: string[];
} {
  let sanitized = text;
  const findings: string[] = [];

  for (const { name, regex } of SECRET_OUTPUT_PATTERNS) {
    if (regex.test(sanitized)) {
      findings.push(name);
      sanitized = sanitized.replace(regex, `[REDACTED:${name}]`);
    }
  }

  return { sanitized, findings };
}
