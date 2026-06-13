// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #8: config layering must ACCUMULATE protection arrays (so a project's
// own contextPolicies/protected* can't silently drop the global ones), and
// KUBE_GUARD_MODE=readonly must be honored.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeConfigLayer, loadConfig } from '../scripts/lib.mjs';

test('issue #8: protection arrays accumulate across layers (global holds)', () => {
  const global = {
    contextPolicies: [{ match: ['*prod*'], level: 'readonly' }],
    protectedNamespaces: ['prod'],
    protectedContexts: ['*prod*'],
  };
  const project = {
    contextPolicies: [{ match: ['kind-*'], level: 'audit' }],
    protectedNamespaces: ['staging'],
  };
  const merged = mergeConfigLayer(global, project);
  assert.equal(merged.contextPolicies.length, 2); // both rules kept
  assert.deepEqual(merged.protectedNamespaces, ['prod', 'staging']);
  assert.deepEqual(merged.protectedContexts, ['*prod*']); // global preserved when project omits it
});

test('issue #8: identical entries are de-duped on merge', () => {
  const merged = mergeConfigLayer({ protectedContexts: ['prod', '*prod*'] }, { protectedContexts: ['prod', 'live'] });
  assert.deepEqual(merged.protectedContexts, ['prod', '*prod*', 'live']);
});

test('issue #8: scalar keys still follow last-wins', () => {
  assert.equal(mergeConfigLayer({ defaultMode: 'strict' }, { defaultMode: 'audit' }).defaultMode, 'audit');
  assert.equal(mergeConfigLayer({ allowExec: false }, { allowExec: true }).allowExec, true);
});

test('issue #8: legacy `mode` in a layer still back-fills defaultMode', () => {
  assert.equal(mergeConfigLayer({}, { mode: 'standard' }).defaultMode, 'standard');
});

test('issue #8: KUBE_GUARD_MODE=readonly is honored (was silently ignored)', () => {
  const prev = process.env.KUBE_GUARD_MODE;
  try {
    process.env.KUBE_GUARD_MODE = 'readonly';
    assert.equal(loadConfig(undefined).defaultMode, 'readonly');
  } finally {
    if (prev === undefined) delete process.env.KUBE_GUARD_MODE;
    else process.env.KUBE_GUARD_MODE = prev;
  }
});
