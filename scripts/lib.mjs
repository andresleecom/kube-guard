// Shared helpers for kube-guard hooks. Zero dependencies (Node stdlib only).
import { existsSync, readFileSync, writeFileSync, appendFileSync, mkdirSync, renameSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

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

const KNOWN_MODES = ['strict', 'standard', 'audit'];

/**
 * Effective config, layered (later wins):
 * plugin defaults -> ~/.claude/kube-guard.config.json (global) ->
 * <project>/.claude/kube-guard.config.json -> KUBE_GUARD_MODE env.
 */
export function loadConfig(proj) {
  let cfg = {
    mode: 'strict',
    contextPolicies: [],
    protectedContexts: ['prod', 'production', '*prod*', '*production*', '*live*'],
    protectedNamespaces: ['kube-system', 'kube-public', 'prod', 'production', '*prod*'],
    allowExec: false,
    allowSecretRead: false,
  };
  const merge = (file) => {
    try {
      if (!existsSync(file)) return;
      const layer = JSON.parse(readFileSync(file, 'utf8'));
      // a layer using the legacy `mode` sets defaultMode for that layer
      if (layer.mode && layer.defaultMode === undefined) layer.defaultMode = layer.mode;
      cfg = { ...cfg, ...layer };
    } catch {
      /* ignore malformed config */
    }
  };
  merge(join(HERE, '..', 'config', 'kube-guard.default.json'));
  merge(join(homedir(), '.claude', 'kube-guard.config.json'));
  if (proj) merge(join(proj, '.claude', 'kube-guard.config.json'));
  const m = process.env.KUBE_GUARD_MODE;
  if (KNOWN_MODES.includes(m)) cfg.defaultMode = cfg.mode = m;
  if (!cfg.defaultMode) cfg.defaultMode = cfg.mode || 'strict';
  return cfg;
}

// ---- leases: temporarily relax a context's posture (the "context leash") ---
export function leasesPath() {
  return join(homedir(), '.claude', 'kube-guard', 'leases.json');
}

export function readLeases() {
  try {
    const p = leasesPath();
    if (!existsSync(p)) return [];
    const arr = JSON.parse(readFileSync(p, 'utf8'));
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

export function writeLeases(arr) {
  try {
    const p = leasesPath();
    mkdirSync(dirname(p), { recursive: true });
    // Write to a temp file and rename: an atomic swap avoids a torn leases.json
    // when concurrent guard.mjs processes write at the same time.
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(arr, null, 2) + '\n', 'utf8');
    renameSync(tmp, p);
    return true;
  } catch {
    return false;
  }
}

/** Leases still in effect at time `now` (ms): not expired and uses remaining. */
export function activeLeases(leases, now) {
  return (leases || []).filter(
    (l) => (l.expiresAt && l.expiresAt > now) || (l.uses != null && l.uses > 0),
  );
}
