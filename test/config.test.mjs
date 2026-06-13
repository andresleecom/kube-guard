// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #4: validateConfig() catches typos/invalid values that would otherwise
// be silently ignored and leave the user on a weaker posture than they think.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateConfig } from '../scripts/lib.mjs';

test('validateConfig accepts a clean config', () => {
  const w = validateConfig({
    defaultMode: 'strict',
    contextPolicies: [{ match: ['*prod*'], level: 'readonly' }],
    protectedContexts: [],
    protectedNamespaces: [],
    allowExec: false,
    allowSecretRead: false,
  });
  assert.deepEqual(w, []);
});

test('validateConfig flags unknown top-level keys (typos)', () => {
  const w = validateConfig({ protectedNamesapces: ['prod'] });
  assert.ok(w.some((m) => m.includes('protectedNamesapces')));
});

test('validateConfig flags invalid level values', () => {
  assert.ok(validateConfig({ defaultMode: 'striict' }).some((m) => /defaultMode/.test(m)));
  assert.ok(
    validateConfig({ contextPolicies: [{ match: ['*prod*'], level: 'readonyl' }] }).some((m) => /level/.test(m)),
  );
});

test('validateConfig flags malformed contextPolicies', () => {
  assert.ok(validateConfig({ contextPolicies: 'nope' }).some((m) => /contextPolicies must be an array/.test(m)));
  assert.ok(validateConfig({ contextPolicies: [{ level: 'strict' }] }).some((m) => /match/.test(m)));
});

test('validateConfig flags wrong types on protected lists and booleans', () => {
  assert.ok(validateConfig({ protectedContexts: 'prod' }).some((m) => /array/.test(m)));
  assert.ok(validateConfig({ allowExec: 'yes' }).some((m) => /true\/false/.test(m)));
});
