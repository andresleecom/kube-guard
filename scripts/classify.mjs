// classify.mjs — pure, no I/O. The heart of kube-guard.
//
// classify(command, config, runtime) -> {
//   verdict: 'allow' | 'ask' | 'deny',
//   klass:   'NONE' | 'READ' | 'WRITE' | 'DESTRUCTIVE' | 'HIGH_RISK' | 'SWITCH' | 'OBFUSCATED' | 'UNKNOWN',
//   reasons: string[],
//   segments: [{ tool, verb, klass, verdict, level, context, namespace, reason }]
// }
//
// Per-context levels (postures), chosen by the target context of EACH command:
//   readonly  -> deny every mutation (reads allow)        [production]
//   strict    -> writes ask, destructive/high-risk deny    [default]
//   standard  -> writes ask, destructive ask, high-risk deny
//   audit     -> allow everything, but the hook logs it    [dev / local]
//
// Design rule: FAIL CLOSED. If we cannot prove a command is safe, ask or deny.

export const DEFAULT_CONFIG = {
  // `defaultMode` is the documented key; `mode` is accepted as a legacy alias.
  // Do not set `defaultMode` here so a user-supplied `mode`/`defaultMode` wins.
  mode: 'strict',
  contextPolicies: [], // [{ match: ["*prod*"], level: "readonly" }]
  protectedContexts: ['prod', 'production', '*prod*', '*production*', '*live*'], // legacy -> readonly
  protectedNamespaces: ['kube-system', 'kube-public', 'prod', 'production', '*prod*'],
  allowExec: false,
  allowSecretRead: false,
};

const STRICTNESS = { allow: 0, ask: 1, deny: 2 };
const strictest = (a, b) => (STRICTNESS[b] > STRICTNESS[a] ? b : a);

// ---- kubectl verb classification ------------------------------------------
const KUBECTL_CLASS = {
  get: 'READ', describe: 'READ', logs: 'READ', log: 'READ', top: 'READ', events: 'READ',
  explain: 'READ', 'api-resources': 'READ', 'api-versions': 'READ', 'cluster-info': 'READ',
  version: 'READ', wait: 'READ', auth: 'READ', diff: 'READ', kustomize: 'READ', completion: 'READ',
  apply: 'WRITE', create: 'WRITE', patch: 'WRITE', edit: 'WRITE', set: 'WRITE', label: 'WRITE',
  annotate: 'WRITE', scale: 'WRITE', autoscale: 'WRITE', expose: 'WRITE', cordon: 'WRITE',
  uncordon: 'WRITE',
  delete: 'DESTRUCTIVE', drain: 'DESTRUCTIVE', taint: 'DESTRUCTIVE', evict: 'DESTRUCTIVE',
  exec: 'HIGH_RISK', cp: 'HIGH_RISK', 'port-forward': 'HIGH_RISK', proxy: 'HIGH_RISK',
  attach: 'HIGH_RISK', debug: 'HIGH_RISK', run: 'HIGH_RISK',
  // special-cased below: replace, rollout, config
};

const HELM_READ = new Set(['list', 'ls', 'status', 'get', 'show', 'history', 'search', 'version', 'env', 'lint', 'template', 'verify', 'inspect']);
const HELM_WRITE = new Set(['install', 'upgrade', 'pull', 'push', 'package', 'create', 'repo', 'registry', 'plugin', 'dependency', 'dep']);
const HELM_DESTRUCTIVE = new Set(['uninstall', 'delete', 'del', 'rollback']);

const VALUE_FLAGS = new Set([
  '-n', '--namespace', '--context', '--cluster', '--user', '--kubeconfig', '--as', '--as-group',
  '--token', '-s', '--server', '--request-timeout', '--cache-dir', '--tls-server-name',
  '--client-key', '--client-certificate', '--certificate-authority', '--password', '--username',
  '--log-flush-frequency', '-o', '--output', '-l', '--selector', '--field-selector', '--kube-context',
]);

// ---- glob helpers ----------------------------------------------------------
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function globMatch(pattern, value) {
  if (!value || !pattern) return false;
  const re = new RegExp('^' + String(pattern).split('*').map(escapeRegex).join('.*') + '$', 'i');
  return re.test(value);
}
export function anyGlob(patterns, value) {
  return Array.isArray(patterns) && patterns.some((p) => globMatch(p, value));
}

// ---- level resolution ------------------------------------------------------
export const KNOWN_LEVELS = ['readonly', 'strict', 'standard', 'audit'];

// Coerce an unknown/typo'd level to a safe posture so a misspelling can never
// silently WEAKEN the guard (e.g. a typo'd policy level dropping deny -> ask).
// Fail closed: the fallback is the strictest posture that fits the source.
export function coerceLevel(level, fallback = 'strict') {
  return KNOWN_LEVELS.includes(level) ? level : fallback;
}

// Returns the posture for a given target context, considering (in order):
// active leases -> contextPolicies -> legacy protectedContexts -> defaultMode.
export function resolveLevel(context, cfg = {}, leases = []) {
  for (const l of leases) {
    if (globMatch(l.context, context)) return coerceLevel(l.level, 'strict');
  }
  for (const p of cfg.contextPolicies || []) {
    if (anyGlob(p.match, context)) return coerceLevel(p.level, 'readonly');
  }
  if (anyGlob(cfg.protectedContexts, context)) return 'readonly';
  return coerceLevel(cfg.defaultMode || cfg.mode, 'strict');
}

function verdictForLevel(klass, level, nsProtected) {
  if (level === 'audit') return 'allow';
  switch (klass) {
    case 'NONE':
    case 'READ':
      return 'allow';
    case 'HIGH_RISK':
      return 'deny';
    case 'OBFUSCATED':
      return level === 'standard' ? 'ask' : 'deny';
    case 'UNKNOWN':
      return 'ask';
    case 'WRITE':
      return level === 'readonly' ? 'deny' : nsProtected ? 'deny' : 'ask';
    case 'DESTRUCTIVE':
      return level === 'readonly' || level === 'strict' ? 'deny' : nsProtected ? 'deny' : 'ask';
    default:
      return 'allow';
  }
}

// ---- shell parsing ---------------------------------------------------------
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

function isObfuscated(cmd) {
  return (
    /\beval\b/.test(cmd) ||
    /\b(?:iex|Invoke-Expression)\b/i.test(cmd) ||
    /\b(?:sh|bash|zsh|dash|pwsh|powershell)\s+-c(?:ommand)?\b/i.test(cmd) ||
    /\bxargs\b/.test(cmd) ||
    /\$\(/.test(cmd) ||
    /`/.test(cmd) ||
    /\|\s*(?:sh|bash|zsh|dash|iex)\b/i.test(cmd) ||
    /\bbase64\b/.test(cmd)
  );
}

function mentionsK8s(s) {
  return /\b(?:kubectl|helm)\b/.test(s) || /\bkubectl\.exe\b/.test(s) || /\bhelm\.exe\b/.test(s);
}

function realCommandTokens(tokens) {
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { i++; continue; }
    if (t === 'sudo' || t === 'command' || t === 'time' || t === 'env' || t === '\\') { i++; continue; }
    break;
  }
  return tokens.slice(i);
}

function baseName(cmd) {
  return (cmd || '').replace(/\.exe$/i, '').split(/[\\/]/).pop();
}

function extractVerbAndArgs(args) {
  const positionals = [];
  const flags = {};
  let verb = null;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t.startsWith('-')) {
      const eq = t.indexOf('=');
      if (eq !== -1) flags[t.slice(0, eq)] = t.slice(eq + 1);
      else if (VALUE_FLAGS.has(t)) { flags[t] = args[i + 1]; i++; }
      else flags[t] = true;
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

// ---- segment builders ------------------------------------------------------
function seg(klass, reason, { context, namespace, runtime, cfg, verb } = {}) {
  const leases = (runtime && runtime.leases) || [];
  const level = resolveLevel(context, cfg, leases);
  const nsProtected = anyGlob(cfg.protectedNamespaces, namespace);
  const verdict = verdictForLevel(klass, level, nsProtected);
  let r = `${reason} [${level}]`;
  if (nsProtected && (klass === 'WRITE' || klass === 'DESTRUCTIVE')) r += ` protected ns ${namespace}`;
  return { tool: 'kubectl/helm', verb: verb ?? null, klass, verdict, level, context: context ?? null, namespace: namespace ?? null, reason: r };
}

function classifyKubectl(args, cfg, runtime) {
  const { verb, positionals, flags } = extractVerbAndArgs(args);
  if (!verb) return seg('UNKNOWN', 'kubectl with no subcommand', { runtime, cfg });

  const context = flagVal(flags, '--context') || (runtime && runtime.currentContext);
  const namespace = flagVal(flags, '-n', '--namespace') || (runtime && runtime.currentNamespace);

  // Safe context SWITCH: evaluate the TARGET context, not the current one.
  if (verb === 'config' && positionals[0] === 'use-context') {
    const target = positionals[1];
    const leases = (runtime && runtime.leases) || [];
    const targetLevel = resolveLevel(target, cfg, leases);
    const verdict = targetLevel === 'audit' ? 'allow' : 'ask';
    const reason =
      targetLevel === 'audit'
        ? `switch to "${target}" (${targetLevel} — free)`
        : `switching INTO guarded context "${target}" (${targetLevel}) — confirm`;
    return { tool: 'kubectl', verb: 'config use-context', klass: 'SWITCH', verdict, level: targetLevel, context: target ?? null, namespace: null, reason };
  }

  let klass = KUBECTL_CLASS[verb];
  if (verb === 'replace') {
    klass = flags['--force'] !== undefined ? 'DESTRUCTIVE' : 'WRITE';
  } else if (verb === 'rollout') {
    const sub = positionals[0];
    klass = sub === 'status' || sub === 'history' ? 'READ' : 'WRITE';
  } else if (verb === 'config') {
    const sub = positionals[0];
    if (sub === 'view') klass = 'HIGH_RISK';
    else if (/^(current-context|get-contexts|get-clusters|get-users)$/.test(sub || '')) klass = 'READ';
    else klass = 'WRITE';
  } else if (verb === 'get' || verb === 'describe') {
    const out = flagVal(flags, '-o', '--output');
    const touchesSecret = positionals.some((p) => /^secrets?(\/|$)/.test(p));
    const dumpsSecret = verb === 'get' && touchesSecret && out && !/^(name|wide)$/.test(out);
    klass = dumpsSecret ? 'HIGH_RISK' : 'READ';
  }

  if (!klass) return seg('UNKNOWN', `unknown kubectl verb "${verb}"`, { verb, context, namespace, runtime, cfg });

  const execFamily = new Set(['exec', 'cp', 'port-forward', 'proxy', 'attach', 'debug', 'run']);
  if (klass === 'HIGH_RISK' && execFamily.has(verb) && cfg.allowExec) klass = 'WRITE';
  if (klass === 'HIGH_RISK' && (verb === 'get' || verb === 'config') && cfg.allowSecretRead) klass = 'WRITE';

  const mutating = klass === 'WRITE' || klass === 'DESTRUCTIVE' || klass === 'HIGH_RISK';
  const wide =
    mutating &&
    (flags['--all'] !== undefined ||
      flags['-A'] !== undefined ||
      flags['--all-namespaces'] !== undefined ||
      flagVal(flags, '-l', '--selector') !== undefined ||
      flags['--force'] !== undefined ||
      flags['--cascade'] !== undefined ||
      String(flagVal(flags, '--grace-period')) === '0');

  const base = `kubectl ${verb} (${klass.toLowerCase()})`;
  return seg(klass, wide ? `${base} wide` : base, { verb, context, namespace, runtime, cfg });
}

function classifyHelm(args, cfg, runtime) {
  const { verb, flags } = extractVerbAndArgs(args);
  if (!verb) return seg('UNKNOWN', 'helm with no subcommand', { runtime, cfg });
  const context = flagVal(flags, '--kube-context', '--context') || (runtime && runtime.currentContext);
  const namespace = flagVal(flags, '-n', '--namespace') || (runtime && runtime.currentNamespace);
  let klass;
  if (HELM_DESTRUCTIVE.has(verb)) klass = 'DESTRUCTIVE';
  else if (HELM_WRITE.has(verb)) klass = 'WRITE';
  else if (HELM_READ.has(verb)) klass = 'READ';
  else return seg('UNKNOWN', `unknown helm subcommand "${verb}"`, { verb, context, namespace, runtime, cfg });
  return seg(klass, `helm ${verb} (${klass.toLowerCase()})`, { verb, context, namespace, runtime, cfg });
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

  if (isObfuscated(command)) {
    const s = seg('OBFUSCATED', 'kubectl/helm wrapped in an unverifiable construct (eval/subshell/pipe-to-shell)', { runtime, cfg });
    return { verdict: s.verdict, klass: 'OBFUSCATED', reasons: [s.reason], segments: [s] };
  }

  for (const segment of splitSegments(command)) {
    const tokens = realCommandTokens(tokenize(segment));
    if (!tokens.length) continue;
    const name = baseName(tokens[0]);
    if (name !== 'kubectl' && name !== 'helm') continue;
    const info = name === 'kubectl' ? classifyKubectl(tokens.slice(1), cfg, runtime) : classifyHelm(tokens.slice(1), cfg, runtime);
    result.segments.push(info);
    const before = result.verdict;
    result.verdict = strictest(result.verdict, info.verdict);
    result.reasons.push(info.reason);
    if (result.verdict !== before || result.klass === 'NONE') result.klass = info.klass;
  }

  if (result.segments.length === 0) {
    const s = seg('OBFUSCATED', 'kubectl/helm present but no parseable invocation', { runtime, cfg });
    return { verdict: s.verdict, klass: 'OBFUSCATED', reasons: [s.reason], segments: [s] };
  }
  return result;
}
