#!/usr/bin/env node
// PreToolUse hook: classify a shell command's kubectl/helm usage and gate it.
// FAIL CLOSED: on any internal error we ASK rather than silently allow.
import { execFileSync } from 'node:child_process';
import { readStdin, projectDir, loadConfig, readLeases, writeLeases, activeLeases } from './lib.mjs';
import { classify, anyGlob } from './classify.mjs';
import { recordDecision } from './audit.mjs';

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

// Best-effort current context/namespace so guards work when the command omits
// --context (the common, most dangerous case).
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

const MUTATIONS = ['WRITE', 'DESTRUCTIVE', 'HIGH_RISK'];

try {
  const input = await readStdin();
  const command = input.tool_input && input.tool_input.command;
  if (typeof command !== 'string' || !/\b(?:kubectl|helm)\b/.test(command)) process.exit(0);

  const proj = projectDir(input);
  const cfg = loadConfig(proj);
  const runtime = resolveRuntime();

  const now = Date.now();
  const allLeases = readLeases();
  runtime.leases = activeLeases(allLeases, now);

  const result = classify(command, cfg, runtime);

  recordDecision(proj, {
    ts: new Date().toISOString(),
    defaultMode: cfg.defaultMode,
    verdict: result.verdict,
    klass: result.klass,
    level: result.segments[0] && result.segments[0].level,
    command,
    reasons: result.reasons,
    context: result.segments[0] && result.segments[0].context,
    namespace: result.segments[0] && result.segments[0].namespace,
    leased: runtime.leases.length ? true : undefined,
  });

  // Consume one-command ("--once") leases that a mutation just used.
  const usedCtxs = result.segments.filter((s) => MUTATIONS.includes(s.klass)).map((s) => s.context);
  if (usedCtxs.length) {
    let changed = false;
    for (const l of allLeases) {
      if (l.uses != null && l.uses > 0 && usedCtxs.some((c) => anyGlob([l.context], c))) {
        l.uses -= 1;
        changed = true;
      }
    }
    if (changed) {
      const pruned = allLeases
        .filter((l) => !(l.uses != null && l.uses <= 0))
        .filter((l) => !(l.expiresAt && l.expiresAt <= now));
      writeLeases(pruned);
    }
  }

  if (result.verdict === 'allow') process.exit(0); // emit nothing = allow
  emit(result.verdict, `kube-guard: ${result.klass} — ${result.reasons.join('; ')}`);
  process.exit(0);
} catch {
  emit('ask', 'kube-guard could not verify this command; asking for confirmation.');
  process.exit(0);
}
