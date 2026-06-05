// audit.mjs — append a kube-guard decision to .claude/kube-guard/audit.jsonl
// Secrets are redacted; the log is kept private via .gitignore. Best-effort.
import { join } from 'node:path';
import { appendJsonl, ensureGitignore, redactSecrets } from './lib.mjs';

export function recordDecision(proj, entry) {
  try {
    const dir = join(proj, '.claude', 'kube-guard');
    const file = join(dir, 'audit.jsonl');
    appendJsonl(file, {
      ...entry,
      command: redactSecrets(entry.command || ''),
      reasons: (entry.reasons || []).map(redactSecrets),
    });
    ensureGitignore(proj, '.claude/kube-guard/', 'kube-guard (audit log, private)');
  } catch {
    /* never block on auditing */
  }
}
