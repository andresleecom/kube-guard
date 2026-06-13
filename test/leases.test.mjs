// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #7: a denied mutation must not burn a one-shot lease; expired leases are
// pruned unconditionally. consumeLeases() and leaseConsumingContexts() are pure.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { consumeLeases, leaseConsumingContexts } from '../scripts/classify.mjs';

const NOW = 1_000_000_000_000; // fixed instant; pure functions take `now`

test('leaseConsumingContexts: a denied mutation is NOT a consuming context', () => {
  const segments = [
    { klass: 'DESTRUCTIVE', verdict: 'deny', context: 'prod-eu' }, // denied -> must not consume
    { klass: 'READ', verdict: 'allow', context: 'prod-eu' }, // reads never consume
  ];
  assert.deepEqual(leaseConsumingContexts(segments), []);
});

test('leaseConsumingContexts: an allowed/asked mutation IS a consuming context', () => {
  const segments = [
    { klass: 'WRITE', verdict: 'ask', context: 'prod-eu' },
    { klass: 'DESTRUCTIVE', verdict: 'allow', context: 'dev-1' },
  ];
  assert.deepEqual(leaseConsumingContexts(segments), ['prod-eu', 'dev-1']);
});

test('consumeLeases: a used one-shot lease decrements and is pruned when spent', () => {
  const leases = [{ context: 'prod-eu', level: 'strict', uses: 1 }];
  const { leases: after, changed } = consumeLeases(leases, ['prod-eu'], NOW);
  assert.equal(changed, true);
  assert.equal(after.length, 0); // uses 1 -> 0 -> pruned
});

test('consumeLeases: an unused one-shot lease is untouched', () => {
  const leases = [{ context: 'prod-eu', uses: 1 }];
  const { leases: after, changed } = consumeLeases(leases, [], NOW);
  assert.equal(changed, false);
  assert.equal(after[0].uses, 1);
});

test('consumeLeases: a one-shot lease for a different context is untouched', () => {
  const leases = [{ context: 'prod-eu', uses: 1 }];
  const { leases: after } = consumeLeases(leases, ['staging'], NOW);
  assert.equal(after[0].uses, 1);
});

test('consumeLeases: a multi-use lease decrements but survives', () => {
  const leases = [{ context: 'prod-eu', uses: 2 }];
  const { leases: after } = consumeLeases(leases, ['prod-eu'], NOW);
  assert.equal(after[0].uses, 1);
});

test('consumeLeases: expired time leases are pruned unconditionally', () => {
  const leases = [
    { context: 'prod-eu', level: 'strict', expiresAt: NOW - 1000 }, // expired
    { context: 'stg', level: 'strict', expiresAt: NOW + 60000 }, // still active
  ];
  const { leases: after, changed } = consumeLeases(leases, [], NOW);
  assert.equal(changed, true);
  assert.deepEqual(after.map((l) => l.context), ['stg']);
});
