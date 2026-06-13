#!/usr/bin/env node
// PreToolUse hook: classify a shell command's kubectl/helm usage and gate it.
// FAIL CLOSED: on any internal error we ASK rather than silently allow.
import { readStdin, projectDir, loadConfig, readLeases, writeLeases, activeLeases, runKubectl } from './lib.mjs';
import { classify, consumeLeases, leaseConsumingContexts, decidingSegment } from './classify.mjs';
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
// --context (the common, most dangerous case). runKubectl resolves the binary
// robustly on Windows so a .cmd/.bat shim can't silently drop this guard.
function resolveRuntime() {
  return {
    currentContext: runKubectl(['config', 'current-context'], 2500) || undefined,
    currentNamespace: runKubectl(['config', 'view', '--minify', '-o', 'jsonpath={..namespace}'], 2500) || undefined,
  };
}

try {
  const input = await readStdin();
  const command = input.tool_input && input.tool_input.command;
  if (typeof command !== 'string') process.exit(0);
  // Strip quotes so intra-word quoting (k'ubectl') can't slip past the fast-path.
  if (!/\b(?:kubectl|helm)\b/.test(command.replace(/['"`]/g, ''))) process.exit(0);

  const proj = projectDir(input);
  const cfg = loadConfig(proj);
  const runtime = resolveRuntime();

  const now = Date.now();
  const allLeases = readLeases();
  runtime.leases = activeLeases(allLeases, now);

  const result = classify(command, cfg, runtime);

  // Attribute the record to the segment that actually set the verdict (the
  // strictest), not blindly segments[0] which may be a harmless leading read.
  const decided = decidingSegment(result) || {};
  recordDecision(proj, {
    ts: new Date().toISOString(),
    defaultMode: cfg.defaultMode,
    verdict: result.verdict,
    klass: result.klass,
    level: decided.level,
    command,
    reasons: result.reasons,
    context: decided.context,
    namespace: decided.namespace,
    leased: runtime.leases.length ? true : undefined,
  });

  // Consume one-command ("--once") leases — but ONLY for mutations that were not
  // denied (a denied command never ran, so it must not burn the lease). Also
  // prunes expired/spent leases unconditionally. Atomic write avoids torn state.
  const { leases: prunedLeases, changed } = consumeLeases(allLeases, leaseConsumingContexts(result.segments), now);
  if (changed) writeLeases(prunedLeases);

  if (result.verdict === 'allow') process.exit(0); // emit nothing = allow
  emit(result.verdict, `kube-guard: ${result.klass} — ${result.reasons.join('; ')}`);
  process.exit(0);
} catch {
  emit('ask', 'kube-guard could not verify this command; asking for confirmation.');
  process.exit(0);
}
