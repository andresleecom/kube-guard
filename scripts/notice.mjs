#!/usr/bin/env node
// PostToolUse hook: kube-guard cannot rewrite tool output, but it CAN warn the
// model when a command's output appears to contain secrets, so the model avoids
// echoing/persisting them. Adds additionalContext only. Fail-safe.
import { readStdin } from './lib.mjs';

const SECRET_HINTS = [
  /-----BEGIN[ A-Z]*PRIVATE KEY-----/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /"?data"?\s*:\s*\{[^}]*[A-Za-z0-9+/]{24,}={0,2}/, // base64-ish data blocks (k8s Secret)
];

try {
  const input = await readStdin();
  const cmd = (input.tool_input && input.tool_input.command) || '';
  if (!/\b(?:kubectl|helm)\b/.test(cmd)) process.exit(0);

  const resp = input.tool_response || {};
  const text = `${resp.stdout || ''}\n${resp.stderr || ''}`;
  if (!SECRET_HINTS.some((re) => re.test(text))) process.exit(0);

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        additionalContext:
          'kube-guard: the previous command output looks like it contains Kubernetes secrets or credentials. ' +
          'Do NOT repeat those values back, write them to files, or include them in summaries; refer to them by name only.',
      },
    }),
  );
  process.exit(0);
} catch {
  process.exit(0);
}
