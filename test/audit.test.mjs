// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #10: audit log must be gitignored at the repo root (even from a monorepo
// subdir) and bounded in size. repoRoot is pure; recordDecision is I/O on temp dirs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { repoRoot } from '../scripts/lib.mjs';
import { recordDecision } from '../scripts/audit.mjs';

const mkTmp = () => mkdtempSync(join(tmpdir(), 'kg-audit-'));

test('repoRoot finds the nearest .git ancestor, or null when there is none', () => {
  const root = mkTmp();
  try {
    mkdirSync(join(root, '.git'));
    const sub = join(root, 'a', 'b');
    mkdirSync(sub, { recursive: true });
    assert.equal(repoRoot(sub), root);
    assert.equal(repoRoot(root), root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  const noGit = mkTmp();
  try {
    assert.equal(repoRoot(noGit), null);
  } finally {
    rmSync(noGit, { recursive: true, force: true });
  }
});

test('recordDecision writes .gitignore at the repo root with the subdir-relative path', () => {
  const root = mkTmp();
  try {
    mkdirSync(join(root, '.git'));
    const sub = join(root, 'pkg');
    mkdirSync(sub);
    recordDecision(sub, { command: 'kubectl get pods', reasons: [] });
    assert.ok(existsSync(join(sub, '.claude', 'kube-guard', 'audit.jsonl'))); // log under the subdir
    const gi = readFileSync(join(root, '.gitignore'), 'utf8'); // .gitignore at the repo root
    assert.match(gi, /pkg\/\.claude\/kube-guard\//);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('recordDecision rotates the audit log past the size cap', () => {
  const proj = mkTmp();
  try {
    const dir = join(proj, '.claude', 'kube-guard');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, 'audit.jsonl');
    writeFileSync(file, 'x'.repeat(6 * 1024 * 1024)); // > 5MB cap
    recordDecision(proj, { command: 'kubectl get pods', reasons: [] });
    assert.ok(existsSync(`${file}.1`)); // rotated to a single rolling backup
  } finally {
    rmSync(proj, { recursive: true, force: true });
  }
});
