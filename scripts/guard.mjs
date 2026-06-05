#!/usr/bin/env node
// PreToolUse hook: classify a Bash command's kubectl/helm usage and gate it.
// FAIL CLOSED: on any internal error we ASK rather than silently allow.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { readStdin, projectDir } from './lib.mjs';
import { classify, DEFAULT_CONFIG } from './classify.mjs';
import { recordDecision } from './audit.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function emit(decision, reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: decision, // 'allow' | 'ask' | 'deny'
        permissionDecisionReason: reason,
      },
    }),
  );
}

function loadConfig(proj) {
  let cfg = { ...DEFAULT_CONFIG };
  // plugin defaults
  try {
    const def = JSON.parse(readFileSync(join(HERE, '..', 'config', 'kube-guard.default.json'), 'utf8'));
    cfg = { ...cfg, ...def };
  } catch {
    /* use built-in defaults */
  }
  // user-global override (applies across every project)
  try {
    const userCfg = join(homedir(), '.claude', 'kube-guard.config.json');
    if (existsSync(userCfg)) cfg = { ...cfg, ...JSON.parse(readFileSync(userCfg, 'utf8')) };
  } catch {
    /* ignore bad user config */
  }
  // per-project override (wins over user-global)
  try {
    const local = join(proj, '.claude', 'kube-guard.config.json');
    if (existsSync(local)) cfg = { ...cfg, ...JSON.parse(readFileSync(local, 'utf8')) };
  } catch {
    /* ignore bad local config */
  }
  // env override for mode
  const m = process.env.KUBE_GUARD_MODE;
  if (m === 'strict' || m === 'standard' || m === 'audit') cfg.mode = m;
  return cfg;
}

// Best-effort current context/namespace so protected guards work when the
// command omits --context (the common, most dangerous case).
function resolveRuntime() {
  const run = (args) => {
    try {
      return execFileSync('kubectl', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 2500 }).trim();
    } catch {
      return '';
    }
  };
  return {
    currentContext: run(['config', 'current-context']) || undefined,
    currentNamespace: run(['config', 'view', '--minify', '-o', 'jsonpath={..namespace}']) || undefined,
  };
}

try {
  const input = await readStdin();
  // Tool-agnostic: any shell tool matched in hooks.json (Bash, PowerShell, ...)
  // carries the command in tool_input.command. Scope is set by the matcher.
  const command = input.tool_input && input.tool_input.command;
  if (typeof command !== 'string' || !/\b(?:kubectl|helm)\b/.test(command)) process.exit(0);

  const proj = projectDir(input);
  const cfg = loadConfig(proj);
  const runtime = resolveRuntime();

  const result = classify(command, cfg, runtime);

  recordDecision(proj, {
    ts: new Date().toISOString(),
    mode: cfg.mode,
    verdict: result.verdict,
    klass: result.klass,
    command,
    reasons: result.reasons,
    context: result.segments[0] && result.segments[0].context,
    namespace: result.segments[0] && result.segments[0].namespace,
  });

  if (result.verdict === 'allow') process.exit(0); // emit nothing = allow

  const reason = `kube-guard (${cfg.mode}): ${result.klass} — ${result.reasons.join('; ')}`;
  emit(result.verdict, reason);
  process.exit(0);
} catch {
  // A guard that errors must not open the door.
  emit('ask', 'kube-guard could not verify this command; asking for confirmation.');
  process.exit(0);
}
