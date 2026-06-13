// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #12: lib.mjs had ZERO tests. Pin the behaviors most likely to break
// subtly: secret redaction, lease-expiry boundaries, gitignore management, and
// config layering precedence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { redactSecrets, activeLeases, ensureGitignore, loadConfig } from '../scripts/lib.mjs';

const mkTmp = () => mkdtempSync(join(tmpdir(), 'kg-test-'));

test('redactSecrets masks high-confidence secret shapes', () => {
  const cases = [
    'AKIAIOSFODNN7EXAMPLE', // AWS access key id
    'sk_live_abcdefghijklmnop', // Stripe-style
    'ghp_abcdefghijklmnopqrstuvwxyz0123456789', // GitHub token
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT', // JWT
    'Bearer abcdefghijklmnopqrstuvwxyz', // bearer token
  ];
  for (const secret of cases) {
    const out = redactSecrets(`token=${secret} end`);
    assert.ok(out.includes('[REDACTED]'), `should redact: ${secret}`);
    assert.ok(!out.includes(secret), `should not leak: ${secret}`);
  }
});

test('redactSecrets masks credentials in URLs and tolerates empty input', () => {
  assert.equal(redactSecrets('https://user:hunter2@host/db'), 'https://[REDACTED]@host/db');
  assert.equal(redactSecrets(''), '');
  assert.equal(redactSecrets(undefined), undefined);
});

test('activeLeases uses a strict > now boundary', () => {
  const now = 1_000_000;
  assert.deepEqual(activeLeases([{ context: 'a', expiresAt: now + 1 }], now).map((l) => l.context), ['a']);
  assert.deepEqual(activeLeases([{ context: 'a', expiresAt: now }], now), []); // == now -> expired
  assert.deepEqual(activeLeases([{ context: 'a', expiresAt: now - 1 }], now), []);
  assert.deepEqual(activeLeases([{ context: 'a', uses: 1 }], now).map((l) => l.context), ['a']);
  assert.deepEqual(activeLeases([{ context: 'a', uses: 0 }], now), []);
  assert.deepEqual(activeLeases([{ context: 'a' }], now), []); // neither field -> dropped
  assert.deepEqual(activeLeases(null, now), []);
});

test('ensureGitignore adds the entry once and is idempotent', () => {
  const dir = mkTmp();
  try {
    ensureGitignore(dir, '.claude/kube-guard/');
    const file = join(dir, '.gitignore');
    assert.ok(existsSync(file));
    const after1 = readFileSync(file, 'utf8');
    assert.ok(after1.includes('.claude/kube-guard/'));
    ensureGitignore(dir, '.claude/kube-guard/'); // second call: no duplicate
    const after2 = readFileSync(file, 'utf8');
    assert.equal(after2.match(/\.claude\/kube-guard\//g).length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadConfig: project layer wins over defaults', () => {
  const proj = mkTmp();
  try {
    mkdirSync(join(proj, '.claude'), { recursive: true });
    writeFileSync(
      join(proj, '.claude', 'kube-guard.config.json'),
      JSON.stringify({ protectedNamespaces: ['kg-test-ns-xyz'] }),
    );
    const cfg = loadConfig(proj);
    assert.deepEqual(cfg.protectedNamespaces, ['kg-test-ns-xyz']); // project replaces the default array
  } finally {
    rmSync(proj, { recursive: true, force: true });
  }
});

test('loadConfig: KUBE_GUARD_MODE env wins (last layer) for a known mode', () => {
  const prev = process.env.KUBE_GUARD_MODE;
  try {
    process.env.KUBE_GUARD_MODE = 'audit';
    assert.equal(loadConfig(mkTmp()).defaultMode, 'audit');
    process.env.KUBE_GUARD_MODE = 'not-a-real-mode';
    assert.notEqual(loadConfig(mkTmp()).defaultMode, 'not-a-real-mode'); // invalid -> ignored
  } finally {
    if (prev === undefined) delete process.env.KUBE_GUARD_MODE;
    else process.env.KUBE_GUARD_MODE = prev;
  }
});
