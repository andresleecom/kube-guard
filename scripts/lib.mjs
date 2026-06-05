// Shared helpers for kube-guard hooks. Zero dependencies (Node stdlib only).
import { existsSync, readFileSync, appendFileSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';

/** Read the hook event JSON from stdin. Never throws: returns {} on any problem. */
export function readStdin() {
  return new Promise((res) => {
    if (process.stdin.isTTY) return res({});
    let data = '';
    process.stdin.setEncoding('utf8');
    const timer = setTimeout(() => res(safeParse(data)), 2500);
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      clearTimeout(timer);
      res(safeParse(data));
    });
    process.stdin.on('error', () => {
      clearTimeout(timer);
      res(safeParse(data));
    });
  });
}

function safeParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/** Resolve (and normalize) the user's project directory. */
export function projectDir(input = {}) {
  return resolve(process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd());
}

/** Append a JSON line to a file, creating parent dirs. Best-effort, never throws. */
export function appendJsonl(file, obj) {
  try {
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, `${JSON.stringify(obj)}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}

/**
 * Idempotently ensure `entry` is gitignored in the given directory.
 * Used to keep the audit log private by default.
 */
export function ensureGitignore(dir, entry, comment = 'kube-guard') {
  try {
    const file = join(dir, '.gitignore');
    const content = existsSync(file) ? readFileSync(file, 'utf8') : '';
    const present = content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .includes(entry);
    if (present) return true;
    const prefix = content.length && !content.endsWith('\n') ? '\n' : '';
    appendFileSync(file, `${prefix}\n# ${comment}\n${entry}\n`);
    return true;
  } catch {
    return false;
  }
}

// Best-effort redaction of high-confidence secret shapes (for the audit log).
const TOKEN_PATTERNS = [
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS access key id
  /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g, // Stripe-style keys
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, // GitHub tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/g, // OpenAI / Anthropic style keys
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google API key
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, // JWT
  /-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g, // PEM
  /\b[Bb]earer\s+[A-Za-z0-9._-]{15,}\b/g, // bearer tokens
];

export function redactSecrets(text) {
  if (!text) return text;
  let out = text;
  for (const re of TOKEN_PATTERNS) out = out.replace(re, '[REDACTED]');
  out = out.replace(/([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s:@]+@/g, '$1[REDACTED]@');
  return out;
}
