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
  // Unverifiable obfuscation must NEVER auto-allow — not even under audit.
  // Checked before the audit short-circuit so it stays fail-closed everywhere.
  if (klass === 'OBFUSCATED') return level === 'strict' || level === 'readonly' ? 'deny' : 'ask';
  if (level === 'audit') return 'allow';
  switch (klass) {
    case 'NONE':
    case 'READ':
      return 'allow';
    case 'HIGH_RISK':
      return 'deny';
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

// ---- lease consumption (pure) ----------------------------------------------
const MUTATION_KLASSES = new Set(['WRITE', 'DESTRUCTIVE', 'HIGH_RISK']);

// Contexts a one-shot lease may be charged for: a mutation that was NOT denied.
// A denied command never ran, so it must never burn the user's single-use lease.
export function leaseConsumingContexts(segments) {
  return (segments || [])
    .filter((s) => MUTATION_KLASSES.has(s.klass) && s.verdict !== 'deny')
    .map((s) => s.context);
}

// Decrement one-shot leases used by `usedContexts`, then drop spent (uses<=0)
// and expired (expiresAt<=now) leases. Pure; returns { leases, changed }.
// Pruning is unconditional so stale time-based leases don't accumulate.
export function consumeLeases(allLeases, usedContexts, now) {
  const leases = allLeases || [];
  let changed = false;
  for (const l of leases) {
    if (l.uses != null && l.uses > 0 && (usedContexts || []).some((c) => globMatch(l.context, c))) {
      l.uses -= 1;
      changed = true;
    }
  }
  const pruned = leases.filter((l) => !(l.uses != null && l.uses <= 0) && !(l.expiresAt && l.expiresAt <= now));
  if (pruned.length !== leases.length) changed = true;
  return { leases: pruned, changed };
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
    // Only ' and " quote here. A backtick is an escape/line-continuation in
    // PowerShell (and bash command-substitution is caught as OBFUSCATED), so
    // treating it as a quote would let a stray ` swallow a real ; | && separator.
    if (c === '"' || c === "'") {
      q = c;
      cur += c;
      continue;
    }
    // '#' starts a comment (to end of line) when at a word boundary — so a
    // trailing comment can't smuggle a destructive verb into the segment.
    if (c === '#' && (i === 0 || /\s/.test(cmd[i - 1]))) {
      while (i + 1 < cmd.length && cmd[i + 1] !== '\n') i++;
      continue;
    }
    const two = cmd.slice(i, i + 2);
    if (two === '&&' || two === '||') {
      segs.push(cur);
      cur = '';
      i++;
      continue;
    }
    // '&' as a background separator — but NOT when it's part of a redirect
    // (2>&1, >&2, &>file), which must stay within the same segment.
    if (c === '&' && cmd[i - 1] !== '>' && cmd[i + 1] !== '>') {
      segs.push(cur);
      cur = '';
      continue;
    }
    if (c === ';' || c === '|' || c === '\n') {
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
    /`[^`]*`/.test(cmd) || // a MATCHED backtick pair = bash command substitution
    /\|\s*(?:sh|bash|zsh|dash|iex)\b/i.test(cmd) ||
    /\bbase64\b/.test(cmd)
  );
}

function mentionsK8s(s) {
  return /\b(?:kubectl|helm)\b/.test(s) || /\bkubectl\.exe\b/.test(s) || /\bhelm\.exe\b/.test(s);
}

// Quoting can split a tool name (k'ubectl' -> kubectl). Strip quotes before any
// relevance probe done on the RAW string (the tokenizer already strips them).
function stripQuotes(s) {
  return (s || '').replace(/['"`]/g, '');
}

function isK8s(name) {
  const n = (name || '').toLowerCase();
  return n === 'kubectl' || n === 'helm';
}

// Commands that may take 'kubectl'/'helm' as an ARGUMENT without executing it.
// Lets us tell a benign mention (which/echo/git/grep) from an unknown command
// that may actually run kubectl (a wrapper) — the latter fails closed.
const BENIGN_LEADERS = new Set([
  'which', 'command', 'type', 'whereis', 'whence', 'where',
  'echo', 'printf', 'print', 'man', 'help', 'info',
  'cat', 'less', 'more', 'head', 'tail', 'tee',
  'grep', 'egrep', 'fgrep', 'rg', 'ag', 'awk', 'sed',
  'git', 'npm', 'npx', 'yarn', 'pnpm', 'make', 'node',
  'get-command', 'get-help', 'gcm', 'select-string', 'sls', 'write-host', 'write-output',
]);

function realCommandTokens(tokens) {
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { i++; continue; }
    if (t === 'sudo' || t === 'time' || t === 'env' || t === '\\') { i++; continue; }
    if (t === 'command') {
      // `command -v/-V/-p NAME` only inspects; `command NAME args` runs NAME.
      if (/^-[vVp]/.test(tokens[i + 1] || '')) break;
      i++; continue;
    }
    break;
  }
  return tokens.slice(i);
}

function baseName(cmd) {
  return (cmd || '').replace(/\.exe$/i, '').split(/[\\/]/).pop();
}

// Short flags that take a value and are commonly written "stuck" to it
// (e.g. -oyaml, -ndefault, -lapp=x). Normalizing them is what stops the
// `kubectl get secret x -oyaml` secret-dump bypass.
const SHORT_VALUE_FLAGS = { o: '-o', n: '-n', l: '-l', s: '-s' };

function extractVerbAndArgs(args) {
  const positionals = [];
  const flags = {};
  let verb = null;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t.startsWith('-')) {
      // Split a stuck short flag: -oyaml / -o=yaml / -ndefault -> { '-o': 'yaml' }.
      const m = !t.startsWith('--') && /^-([onls])(.+)$/.exec(t);
      if (m) {
        flags[SHORT_VALUE_FLAGS[m[1]]] = m[2][0] === '=' ? m[2].slice(1) : m[2];
        continue;
      }
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

// Does a positional reference the Secret resource? kubectl accepts comma-joined
// lists (secrets,configmaps / configmaps,secrets), name forms (secret/foo) and
// fully-qualified names (secret.v1.core/foo) — all of which must be caught.
function touchesSecretResource(positional) {
  return String(positional)
    .split(',')
    .some((p) => /^secrets?([./]|$)/i.test(p.trim()));
}

// Does a positional reference an RBAC kind (Role/ClusterRole and their
// bindings)? Mutating these grants/revokes privileges — a privilege escalation
// path. Handles comma lists, name forms and fully-qualified group names.
function targetsRbac(positional) {
  return String(positional)
    .split(',')
    .some((p) => /^(clusterrolebindings?|rolebindings?|clusterroles?|roles?)([./]|$)/i.test(p.trim()));
}

const RBAC_MUTATORS = new Set(['create', 'apply', 'patch', 'replace', 'edit', 'set', 'label', 'annotate']);

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
  } else if (verb === 'auth') {
    // `auth reconcile` creates/updates RBAC (privilege-granting); `auth can-i`
    // and `auth whoami` only read.
    klass = positionals[0] === 'reconcile' ? 'HIGH_RISK' : 'READ';
  } else if (verb === 'get' || verb === 'describe') {
    const out = flagVal(flags, '-o', '--output');
    const tmpl = flagVal(flags, '--template', '--go-template', '--go-template-file', '--template-file');
    const touchesSecret = positionals.some(touchesSecretResource);
    // name/wide only print metadata; any other output (yaml/json/jsonpath/
    // custom-columns/go-template/...) can reveal the base64 `.data` of a Secret.
    const exposes = (out !== undefined && !/^(name|wide)$/.test(out)) || tmpl !== undefined;
    const dumpsSecret = verb === 'get' && touchesSecret && exposes;
    klass = dumpsSecret ? 'HIGH_RISK' : 'READ';
  }

  // apply --prune deletes live objects not in the applied set -> destructive.
  if (verb === 'apply' && flags['--prune'] !== undefined) klass = 'DESTRUCTIVE';

  // create/apply/patch/... of an RBAC kind grants or revokes privileges.
  if (RBAC_MUTATORS.has(verb) && positionals.some(targetsRbac)) klass = 'HIGH_RISK';

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
  const { verb, positionals, flags } = extractVerbAndArgs(args);
  if (!verb) return seg('UNKNOWN', 'helm with no subcommand', { runtime, cfg });
  const context = flagVal(flags, '--kube-context', '--context') || (runtime && runtime.currentContext);
  const namespace = flagVal(flags, '-n', '--namespace') || (runtime && runtime.currentNamespace);
  let klass;
  if (HELM_DESTRUCTIVE.has(verb)) klass = 'DESTRUCTIVE';
  else if (HELM_WRITE.has(verb)) klass = 'WRITE';
  else if (HELM_READ.has(verb)) klass = 'READ';
  else return seg('UNKNOWN', `unknown helm subcommand "${verb}"`, { verb, context, namespace, runtime, cfg });

  // `helm get manifest|values|all|hooks` prints rendered release contents, which
  // routinely include Secret `.data` and plaintext credentials from values.yaml.
  if (verb === 'get' && /^(manifest|values|all|hooks)$/.test(positionals[0] || '')) {
    klass = cfg.allowSecretRead ? 'WRITE' : 'HIGH_RISK';
    const reason = klass === 'HIGH_RISK' ? `helm get ${positionals[0]} (high_risk: exposes release secrets)` : `helm get ${positionals[0]} (write: secret read allowed)`;
    return seg(klass, reason, { verb, context, namespace, runtime, cfg });
  }
  return seg(klass, `helm ${verb} (${klass.toLowerCase()})`, { verb, context, namespace, runtime, cfg });
}

// ---- public API ------------------------------------------------------------
export function classify(command, config = {}, runtime = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const result = { verdict: 'allow', klass: 'NONE', reasons: [], segments: [] };

  if (typeof command !== 'string' || !command.trim()) {
    return { verdict: 'allow', klass: 'NONE', reasons: ['empty command'], segments: [] };
  }

  // Tokenize FIRST so quoting cannot hide the tool name (k'ubectl' -> kubectl).
  const segTokens = splitSegments(command).map((s) => realCommandTokens(tokenize(s)));
  const invokesK8s = segTokens.some((toks) => toks.length && isK8s(baseName(toks[0])));
  const k8sAsArg = segTokens.some((toks) => toks.slice(1).some((t) => isK8s(baseName(t))));

  // Obfuscation: an unverifiable construct AROUND kubectl/helm fails closed.
  // Probe with quotes stripped so eval "k'ubectl' ..." cannot evade detection.
  // Evaluate against the live context so obfuscation aimed at a protected
  // (readonly) cluster is denied, not merely asked, even under an audit default.
  if (isObfuscated(command) && mentionsK8s(stripQuotes(command))) {
    const context = runtime && runtime.currentContext;
    const s = seg('OBFUSCATED', 'kubectl/helm wrapped in an unverifiable construct (eval/subshell/pipe-to-shell)', { context, runtime, cfg });
    return { verdict: s.verdict, klass: 'OBFUSCATED', reasons: [s.reason], segments: [s] };
  }

  // kubectl/helm never appear as runnable tokens (only inside quoted strings,
  // comments, or not at all) -> nothing for us to guard.
  if (!invokesK8s && !k8sAsArg) {
    return { verdict: 'allow', klass: 'NONE', reasons: ['no kubectl/helm invocation'], segments: [] };
  }

  const add = (info) => {
    result.segments.push(info);
    const before = result.verdict;
    result.verdict = strictest(result.verdict, info.verdict);
    result.reasons.push(info.reason);
    if (result.verdict !== before || result.klass === 'NONE') result.klass = info.klass;
  };

  for (const tokens of segTokens) {
    if (!tokens.length) continue;
    const name = baseName(tokens[0]);
    if (isK8s(name)) {
      add(name.toLowerCase() === 'kubectl'
        ? classifyKubectl(tokens.slice(1), cfg, runtime)
        : classifyHelm(tokens.slice(1), cfg, runtime));
      continue;
    }
    // Leader is not kubectl/helm. Does this segment hand kubectl/helm to an
    // unrecognized wrapper (timeout/nice/parallel/...)? If so, fail closed.
    if (tokens.slice(1).some((t) => isK8s(baseName(t))) && !BENIGN_LEADERS.has(name.toLowerCase())) {
      add(seg('OBFUSCATED', `kubectl/helm run via unrecognized wrapper "${name}"`, { runtime, cfg }));
    }
    // else: a benign inspector (which/echo/git/...) merely referencing kubectl.
  }

  if (result.segments.length === 0) {
    // kubectl/helm appeared only in benign positions -> allow.
    return { verdict: 'allow', klass: 'NONE', reasons: ['kubectl/helm referenced but not invoked'], segments: [] };
  }
  return result;
}
