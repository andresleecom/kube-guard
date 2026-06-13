// audit.mjs — append a kube-guard decision to .claude/kube-guard/audit.jsonl
// Secrets are redacted; the log is kept private via .gitignore. Best-effort.
import { join, relative, sep } from 'node:path';
import { existsSync, statSync, renameSync } from 'node:fs';
import { appendJsonl, ensureGitignore, redactSecrets, repoRoot } from './lib.mjs';
import { anyGlob } from './classify.mjs';

const MAX_AUDIT_BYTES = 5 * 1024 * 1024; // rotate past ~5MB to keep the log bounded

/**
 * Roll up audit entries into counts and top offenders. Pure. `opts`:
 *   sinceTs?: number   — keep entries at/after this epoch-ms cutoff
 *   denyOnly?: boolean — keep only denied entries
 *   contextGlob?: string — keep only entries whose context matches the glob
 */
export function summarizeAudit(entries, opts = {}) {
  const out = {
    total: 0,
    byVerdict: { allow: 0, ask: 0, deny: 0 },
    byKlass: {},
    deniesByContext: {},
    topDenied: [],
  };
  const deniedCounts = new Map();
  for (const e of entries || []) {
    if (!e || typeof e !== 'object') continue;
    if (opts.sinceTs != null) {
      const t = Date.parse(e.ts);
      if (!(t >= opts.sinceTs)) continue;
    }
    if (opts.denyOnly && e.verdict !== 'deny') continue;
    if (opts.contextGlob && !anyGlob([opts.contextGlob], e.context)) continue;

    out.total++;
    if (e.verdict in out.byVerdict) out.byVerdict[e.verdict]++;
    if (e.klass) out.byKlass[e.klass] = (out.byKlass[e.klass] || 0) + 1;
    if (e.verdict === 'deny') {
      const ctx = e.context || '(none)';
      out.deniesByContext[ctx] = (out.deniesByContext[ctx] || 0) + 1;
      const cmd = e.command || '(unknown)';
      deniedCounts.set(cmd, (deniedCounts.get(cmd) || 0) + 1);
    }
  }
  out.topDenied = [...deniedCounts.entries()]
    .map(([command, count]) => ({ command, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  return out;
}

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
