// audit.mjs — append a kube-guard decision to .claude/kube-guard/audit.jsonl
// Secrets are redacted; the log is kept private via .gitignore. Best-effort.
import { join, relative, sep } from 'node:path';
import { existsSync, statSync, renameSync } from 'node:fs';
import { appendJsonl, ensureGitignore, redactSecrets, repoRoot } from './lib.mjs';

const MAX_AUDIT_BYTES = 5 * 1024 * 1024; // rotate past ~5MB to keep the log bounded

export function recordDecision(proj, entry) {
  try {
    const dir = join(proj, '.claude', 'kube-guard');
    const file = join(dir, 'audit.jsonl');

    // Keep the log bounded: roll over to a single backup once it gets large.
    try {
      if (existsSync(file) && statSync(file).size > MAX_AUDIT_BYTES) renameSync(file, `${file}.1`);
    } catch {
      /* ignore rotation problems */
    }

    appendJsonl(file, {
      ...entry,
      command: redactSecrets(entry.command || ''),
      reasons: (entry.reasons || []).map(redactSecrets),
    });

    // Write .gitignore at the git repo root (not just CLAUDE_PROJECT_DIR) so the
    // log is ignored even when the project dir is a monorepo subdirectory. Skip
    // entirely when there is no repo (nothing to ignore).
    const root = repoRoot(proj);
    if (root) {
      const rel = relative(root, dir).split(sep).join('/');
      ensureGitignore(root, `${rel}/`, 'kube-guard (audit log, private)');
    }
  } catch {
    /* never block on auditing */
  }
}
