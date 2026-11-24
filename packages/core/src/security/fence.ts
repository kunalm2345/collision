import fs from 'node:fs';
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
  'pip3 ',
  'pipx ',
  'python ',
  'python3 ',
  'go ',
  'cargo ',
  'tsc',
  'which ',
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

const UNTRUSTED_CONTENT_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  {
    name: 'prompt-injection-ignore-instructions',
    regex: /\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system|developer)\s+(?:instructions|prompts|rules)\b/i,
  },
  {
    name: 'prompt-injection-exfiltrate-env',
    regex: /\b(?:exfiltrate|send|post|upload|leak)\b[^\n]{0,80}(?:^|[\s"'`/\\])\.env(?![\w.-]*\.(?:example|sample|template)\b)(?:\b|\.)/i,
  },
  {
    name: 'remote-shell-pipe',
    regex: /\b(?:curl|wget)\b[^\n|]{0,120}\|\s*(?:sh|bash|zsh)\b/i,
  },
  {
    name: 'encoded-shell-exec',
    regex: /\bbase64\s+(?:-d|--decode)\b[^\n|]{0,80}\|\s*(?:sh|bash|zsh)\b/i,
  },
  {
    name: 'zero-width-obfuscation',
    regex: /[\u200B-\u200D\uFEFF]{6,}/,
  },
];

export interface SecurityPolicy {
  projectDir: string;
  allowBash: boolean;
  extraBlockedPaths?: string[];
  allowedBashPrefixes?: string[];
}

function checkSingleResolvedPath(
  targetPath: string,
  resolved: string,
  projectRoot: string,
  policy: SecurityPolicy,
): string | null {
  const rel = path.relative(projectRoot, resolved);

  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return `Path "${targetPath}" escapes the project directory`;
  }

  const base = path.basename(resolved);
  const baseLower = base.toLowerCase();
  if (
    baseLower.startsWith('.env') &&
    !baseLower.endsWith('.example') &&
    !baseLower.endsWith('.sample') &&
    !baseLower.endsWith('.template')
  ) {
    return `Reading "${base}" is blocked to keep secrets off the LLM`;
  }

  if (DEFAULT_BLOCKED_BASENAMES.has(baseLower)) {
    return `Reading "${base}" is blocked by Collision security policy`;
  }

  const relLower = rel.toLowerCase();
  for (const extra of policy.extraBlockedPaths ?? []) {
    const extraLower = extra.toLowerCase();
    if (relLower === extraLower || relLower.startsWith(`${extraLower}${path.sep}`)) {
      return `Reading "${rel}" is blocked by vendor security policy`;
    }
  }

  return null;
}

export function isPathBlockedForModelRead(
  targetPath: string,
  policy: SecurityPolicy,
): string | null {
  const projectRoot = path.resolve(policy.projectDir);
  const resolved = path.resolve(projectRoot, targetPath);

  const directCheck = checkSingleResolvedPath(targetPath, resolved, projectRoot, policy);
  if (directCheck) return directCheck;

  try {
    if (fs.existsSync(resolved)) {
      const realRoot = fs.existsSync(projectRoot) ? fs.realpathSync(projectRoot) : projectRoot;
      const realTarget = fs.realpathSync(resolved);
      const realCheck = checkSingleResolvedPath(targetPath, realTarget, realRoot, policy);
      if (realCheck) return realCheck;
    }
  } catch {
    return `Path "${targetPath}" could not be safely resolved`;
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

  // Reject command substitution (`$(...)` or backticks) which can smuggle arbitrary commands.
  if (/\$\(|`/.test(trimmed)) {
    return 'Command substitution ($() or backticks) is blocked by Collision security policy';
  }

  // Split chained shell commands (;, &&, ||, newline) outside quotes and validate every segment.
  const segments = splitShellSegments(trimmed);
  for (const segment of segments) {
    const seg = segment.trim();
    if (!seg) continue;
    // Allow simple output pipes to safe read-only filters (head/tail) on the right-hand side.
    const pipeParts = seg.split('|').map((p) => p.trim());
    const primary = pipeParts[0];
    const allowed = prefixes.some(
      (prefix) => primary === prefix.trim() || primary.startsWith(prefix),
    );
    if (!allowed) {
      return `Command "${primary.split(/\s+/)[0]}" is not in the bash allowlist`;
    }
    for (let i = 1; i < pipeParts.length; i++) {
      const rhs = pipeParts[i];
      if (!rhs) continue;
      const rhsCmd = rhs.split(/\s+/)[0];
      if (rhsCmd !== 'head' && rhsCmd !== 'tail' && rhsCmd !== 'wc') {
        return `Piped command "${rhsCmd}" is not in the bash allowlist`;
      }
    }
  }

  return null;
}

function splitShellSegments(command: string): string[] {
  const segments: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const next = command[i + 1];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
    } else if (!inSingle && !inDouble) {
      if (ch === ';' || ch === '\n') {
        segments.push(current);
        current = '';
      } else if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
        segments.push(current);
        current = '';
        i++;
      } else {
        current += ch;
      }
    } else {
      current += ch;
    }
  }
  if (current) segments.push(current);
  return segments;
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

export function scanUntrustedContent(text: string): {
  safe: boolean;
  findings: string[];
} {
  const findings: string[] = [];
  const normalized = text.normalize('NFKC');
  for (const { name, regex } of UNTRUSTED_CONTENT_PATTERNS) {
    const subject = name === 'zero-width-obfuscation' ? text : normalized;
    if (regex.test(subject)) {
      findings.push(name);
    }
  }
  return { safe: findings.length === 0, findings };
}
