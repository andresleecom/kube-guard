// classify.mjs — pure, no I/O. The heart of kube-guard.
//
// classify(command, config, runtime) -> {
//   verdict: 'allow' | 'ask' | 'deny',
//   klass:   'NONE' | 'READ' | 'WRITE' | 'DESTRUCTIVE' | 'HIGH_RISK' | 'OBFUSCATED' | 'UNKNOWN',
//   reasons: string[],
//   segments: [{ tool, verb, klass, verdict, context, namespace, reason }]
// }
//
// Design rule: FAIL CLOSED. If we cannot prove a command is safe, we ask or deny —
// never silently allow.

export const DEFAULT_CONFIG = {
  mode: 'strict', // 'strict' | 'standard' | 'audit'
  protectedContexts: ['prod', 'production', '*prod*', '*production*', '*live*'],
  protectedNamespaces: ['kube-system', 'kube-public', 'prod', 'production', '*prod*'],
  allowExec: false,
  allowSecretRead: false,
};

const STRICTNESS = { allow: 0, ask: 1, deny: 2 };
const strictest = (a, b) => (STRICTNESS[b] > STRICTNESS[a] ? b : a);

// ---- kubectl verb classification ------------------------------------------
const KUBECTL_CLASS = {
  // READ
  get: 'READ', describe: 'READ', logs: 'READ', log: 'READ', top: 'READ', events: 'READ',
  explain: 'READ', 'api-resources': 'READ', 'api-versions': 'READ', 'cluster-info': 'READ',
  version: 'READ', wait: 'READ', auth: 'READ', diff: 'READ', kustomize: 'READ', completion: 'READ',
  // WRITE
  apply: 'WRITE', create: 'WRITE', patch: 'WRITE', edit: 'WRITE', set: 'WRITE', label: 'WRITE',
  annotate: 'WRITE', scale: 'WRITE', autoscale: 'WRITE', expose: 'WRITE', cordon: 'WRITE',
  uncordon: 'WRITE', apply_: 'WRITE',
  // DESTRUCTIVE
  delete: 'DESTRUCTIVE', drain: 'DESTRUCTIVE', taint: 'DESTRUCTIVE', evict: 'DESTRUCTIVE',
  // HIGH_RISK (arbitrary code / data exfiltration vectors)
  exec: 'HIGH_RISK', cp: 'HIGH_RISK', 'port-forward': 'HIGH_RISK', proxy: 'HIGH_RISK',
  attach: 'HIGH_RISK', debug: 'HIGH_RISK', run: 'HIGH_RISK',
  // special-cased below: replace, rollout, config
};

const HELM_READ = new Set(['list', 'ls', 'status', 'get', 'show', 'history', 'search', 'version', 'env', 'lint', 'template', 'verify', 'inspect']);
const HELM_WRITE = new Set(['install', 'upgrade', 'pull', 'push', 'package', 'create', 'repo', 'registry', 'plugin', 'dependency', 'dep']);
const HELM_DESTRUCTIVE = new Set(['uninstall', 'delete', 'del', 'rollback']);

// kubectl global flags that consume the following token as their value.
const VALUE_FLAGS = new Set([
  '-n', '--namespace', '--context', '--cluster', '--user', '--kubeconfig', '--as', '--as-group',
  '--token', '-s', '--server', '--request-timeout', '--cache-dir', '--tls-server-name',
  '--client-key', '--client-certificate', '--certificate-authority', '--password', '--username',
  '--log-flush-frequency', '-o', '--output', '-l', '--selector', '--field-selector',
]);

// ---- helpers ---------------------------------------------------------------

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function globMatch(pattern, value) {
  if (!value) return false;
  const re = new RegExp('^' + pattern.split('*').map(escapeRegex).join('.*') + '$', 'i');
  return re.test(value);
}

function anyGlob(patterns, value) {
  return Array.isArray(patterns) && patterns.some((p) => globMatch(p, value));
}

// Split a command into segments on shell control operators (&& || ; | newline),
// respecting single/double quotes and backticks.
export function splitSegments(cmd) {
  const segs = [];
  let cur = '';
  let q = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (q) {
      cur += c;
      if (c === q) q = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      q = c;
      cur += c;
      continue;
    }
    const two = cmd.slice(i, i + 2);
    if (two === '&&' || two === '||') {
      segs.push(cur);
      cur = '';
      i++;
      continue;
    }
    if (c === ';' || c === '|' || c === '\n' || c === '&') {
      segs.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  segs.push(cur);
  return segs.map((s) => s.trim()).filter(Boolean);
}

// Tokenize a single segment respecting quotes (quotes stripped from tokens).
function tokenize(seg) {
  const out = [];
  let cur = '';
  let q = null;
  let has = false;
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (q) {
      if (c === q) q = null;
      else cur += c;
      has = true;
      continue;
    }
    if (c === '"' || c === "'") {
      q = c;
      has = true;
      continue;
    }
    if (/\s/.test(c)) {
      if (has) out.push(cur);
      cur = '';
      has = false;
      continue;
    }
    cur += c;
    has = true;
  }
  if (has) out.push(cur);
  return out;
}

// Whole-command obfuscation: constructs that defeat static analysis. If the
// command also references kubectl/helm, we cannot trust per-segment parsing.
function isObfuscated(cmd) {
  return (
    /\beval\b/.test(cmd) ||
    /\b(?:sh|bash|zsh|dash)\s+-c\b/.test(cmd) ||
    /\bxargs\b/.test(cmd) ||
    /\$\(/.test(cmd) ||
    /`/.test(cmd) ||
    /\|\s*(?:sh|bash|zsh|dash)\b/.test(cmd) ||
    /\bbase64\b/.test(cmd)
  );
}

function mentionsK8s(s) {
  return /\b(?:kubectl|helm)\b/.test(s) || /\bkubectl\.exe\b/.test(s) || /\bhelm\.exe\b/.test(s);
}

// Strip leading env-assignments and benign prefixes, return tokens for the real command.
function realCommandTokens(tokens) {
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { i++; continue; } // FOO=bar
    if (t === 'sudo' || t === 'command' || t === 'time' || t === 'env' || t === '\\') { i++; continue; }
    break;
  }
  return tokens.slice(i);
}

function baseName(cmd) {
  return (cmd || '').replace(/\.exe$/i, '').split(/[\\/]/).pop();
}

// Find the verb (first non-flag token, skipping global flags + their values).
function extractVerbAndArgs(args) {
  const positionals = [];
  const flags = {};
  let verb = null;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t.startsWith('-')) {
      const eq = t.indexOf('=');
      if (eq !== -1) {
        flags[t.slice(0, eq)] = t.slice(eq + 1);
      } else if (VALUE_FLAGS.has(t)) {
        flags[t] = args[i + 1];
        i++;
      } else {
        flags[t] = true;
      }
      continue;
    }
    if (verb === null) verb = t;
    else positionals.push(t);
  }
  return { verb, positionals, flags };
}

function flagVal(flags, ...names) {
  for (const n of names) if (flags[n] !== undefined) return flags[n];
  return undefined;
}

// ---- segment classification ------------------------------------------------

function classifyKubectl(args, cfg, runtime) {
  const { verb, positionals, flags } = extractVerbAndArgs(args);
  if (!verb) return seg('UNKNOWN', 'kubectl with no subcommand', { verb: null, flags, runtime, cfg });

  const context = flagVal(flags, '--context') || runtime.currentContext;
  const namespace = flagVal(flags, '-n', '--namespace') || runtime.currentNamespace;
  let klass = KUBECTL_CLASS[verb];

  // special cases
  if (verb === 'replace') {
    klass = flags['--force'] !== undefined ? 'DESTRUCTIVE' : 'WRITE';
  } else if (verb === 'rollout') {
    const sub = positionals[0];
    klass = (sub === 'status' || sub === 'history') ? 'READ' : 'WRITE';
  } else if (verb === 'config') {
    const sub = positionals[0];
    if (sub === 'view') klass = 'HIGH_RISK'; // may expose tokens/certs
    else if (/^(current-context|get-contexts|get-clusters|get-users)$/.test(sub || '')) klass = 'READ';
    else klass = 'WRITE'; // use-context, set*, unset, delete-context
  } else if (verb === 'get' || verb === 'describe') {
    // secret dumps: `get secret` with any output format that can reveal data
    // (yaml/json/jsonpath/go-template/...) exposes base64 values. `-o name`/`-o wide`
    // and a bare `get secrets` (names only) are fine. `describe` redacts -> READ.
    const out = flagVal(flags, '-o', '--output');
    const touchesSecret = positionals.some((p) => /^secrets?(\/|$)/.test(p));
    const dumpsSecret = verb === 'get' && touchesSecret && out && !/^(name|wide)$/.test(out);
    klass = dumpsSecret ? 'HIGH_RISK' : 'READ';
  }

  if (!klass) return seg('UNKNOWN', `unknown kubectl verb "${verb}"`, { verb, flags, context, namespace, runtime, cfg });

  // allow-flags downgrade certain HIGH_RISK classes
  const execFamily = new Set(['exec', 'cp', 'port-forward', 'proxy', 'attach', 'debug', 'run']);
  if (klass === 'HIGH_RISK' && execFamily.has(verb) && cfg.allowExec) klass = 'WRITE';
  if (klass === 'HIGH_RISK' && (verb === 'get' || verb === 'config') && cfg.allowSecretRead) klass = 'WRITE';

  // blast-radius flags bump a WRITE toward destructive territory
  const wide =
    flags['--all'] !== undefined ||
    flags['-A'] !== undefined ||
    flags['--all-namespaces'] !== undefined ||
    flagVal(flags, '-l', '--selector') !== undefined ||
    flags['--force'] !== undefined ||
    flags['--cascade'] !== undefined ||
    String(flagVal(flags, '--grace-period')) === '0';

  return seg(klass, describe(verb, klass, wide), { verb, flags, context, namespace, wide, runtime, cfg });
}

function classifyHelm(args, cfg, runtime) {
  const { verb, flags } = extractVerbAndArgs(args);
  if (!verb) return seg('UNKNOWN', 'helm with no subcommand', { verb: null, flags, runtime, cfg });
  const context = flagVal(flags, '--kube-context', '--context') || runtime.currentContext;
  const namespace = flagVal(flags, '-n', '--namespace') || runtime.currentNamespace;
  let klass;
  if (HELM_DESTRUCTIVE.has(verb)) klass = 'DESTRUCTIVE';
  else if (HELM_WRITE.has(verb)) klass = 'WRITE';
  else if (HELM_READ.has(verb)) klass = 'READ';
  else return seg('UNKNOWN', `unknown helm subcommand "${verb}"`, { verb, flags, context, namespace, runtime, cfg });
  return seg(klass, `helm ${verb} (${klass.toLowerCase()})`, { verb, flags, context, namespace, runtime, cfg });
}

function describe(verb, klass, wide) {
  const base = `kubectl ${verb} (${klass.toLowerCase()})`;
  return wide ? `${base} with wide blast radius` : base;
}

// Build a segment result + verdict given class and protected-context check.
function seg(klass, reason, { context, namespace, runtime, cfg, verb } = {}) {
  const protectedHit =
    anyGlob(cfg.protectedContexts, context) || anyGlob(cfg.protectedNamespaces, namespace);
  const verdict = verdictFor(klass, cfg.mode, protectedHit);
  let r = reason;
  if (protectedHit && (klass === 'WRITE' || klass === 'DESTRUCTIVE' || klass === 'HIGH_RISK')) {
    r += ` on protected target (context=${context ?? '?'}, ns=${namespace ?? '?'})`;
  }
  return { tool: 'kubectl/helm', verb: verb ?? null, klass, verdict, context: context ?? null, namespace: namespace ?? null, reason: r };
}

function verdictFor(klass, mode, protectedHit) {
  if (mode === 'audit') return 'allow';
  switch (klass) {
    case 'READ': return 'allow';
    case 'WRITE': return protectedHit ? 'deny' : 'ask';
    case 'DESTRUCTIVE': return protectedHit || mode === 'strict' ? 'deny' : 'ask';
    case 'HIGH_RISK': return 'deny';
    case 'OBFUSCATED': return mode === 'strict' ? 'deny' : 'ask';
    case 'UNKNOWN': return 'ask';
    default: return 'allow';
  }
}

// ---- public API ------------------------------------------------------------

export function classify(command, config = {}, runtime = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const result = { verdict: 'allow', klass: 'NONE', reasons: [], segments: [] };

  if (typeof command !== 'string' || !command.trim()) {
    return { verdict: 'allow', klass: 'NONE', reasons: ['empty command'], segments: [] };
  }
  if (!mentionsK8s(command)) {
    return { verdict: 'allow', klass: 'NONE', reasons: ['no kubectl/helm'], segments: [] };
  }

  // Fail-closed obfuscation gate: kubectl/helm + a construct that hides it.
  if (isObfuscated(command)) {
    const s = seg('OBFUSCATED', 'kubectl/helm wrapped in an unverifiable construct (eval/subshell/pipe-to-shell)', { cfg });
    return { verdict: s.verdict, klass: 'OBFUSCATED', reasons: [s.reason], segments: [s] };
  }

  for (const segment of splitSegments(command)) {
    const tokens = realCommandTokens(tokenize(segment));
    if (!tokens.length) continue;
    const name = baseName(tokens[0]);
    if (name !== 'kubectl' && name !== 'helm') continue; // not a k8s command (e.g. echo, cd)
    const info =
      name === 'kubectl'
        ? classifyKubectl(tokens.slice(1), cfg, runtime)
        : classifyHelm(tokens.slice(1), cfg, runtime);
    result.segments.push(info);
    result.verdict = strictest(result.verdict, info.verdict);
    result.reasons.push(info.reason);
    if (STRICTNESS[info.verdict] >= STRICTNESS[result.verdict]) result.klass = info.klass;
  }

  // We saw a kubectl/helm token but couldn't isolate a real invocation -> fail closed.
  if (result.segments.length === 0) {
    const s = seg('OBFUSCATED', 'kubectl/helm present but no parseable invocation', { cfg });
    return { verdict: s.verdict, klass: 'OBFUSCATED', reasons: [s.reason], segments: [s] };
  }

  if (cfg.mode === 'audit') result.verdict = 'allow';
  return result;
}
