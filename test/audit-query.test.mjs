// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #15: summarizeAudit() rolls up audit.jsonl entries (counts, top denied,
// by-context) with optional since/deny-only/context filters. Pure & testable;
// the audit-query.mjs CLI just reads the file and prints the result.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeAudit } from '../scripts/audit.mjs';

const ENTRIES = [
  { ts: '2026-06-13T10:00:00Z', verdict: 'allow', klass: 'READ', command: 'kubectl get pods', context: 'dev' },
  { ts: '2026-06-13T11:00:00Z', verdict: 'deny', klass: 'DESTRUCTIVE', command: 'kubectl delete ns prod', context: 'prod' },
  { ts: '2026-06-13T12:00:00Z', verdict: 'deny', klass: 'DESTRUCTIVE', command: 'kubectl delete ns prod', context: 'prod' },
  { ts: '2026-06-13T13:00:00Z', verdict: 'ask', klass: 'WRITE', command: 'kubectl apply -f x', context: 'staging' },
];

test('summarizeAudit counts by verdict and class', () => {
  const s = summarizeAudit(ENTRIES, {});
  assert.equal(s.total, 4);
  assert.deepEqual(s.byVerdict, { allow: 1, ask: 1, deny: 2 });
  assert.equal(s.byKlass.DESTRUCTIVE, 2);
  assert.equal(s.byKlass.READ, 1);
});

test('summarizeAudit surfaces the top denied commands and denies by context', () => {
  const s = summarizeAudit(ENTRIES, {});
  assert.equal(s.topDenied[0].command, 'kubectl delete ns prod');
  assert.equal(s.topDenied[0].count, 2);
  assert.equal(s.deniesByContext.prod, 2);
});

test('summarizeAudit honors the deny-only filter', () => {
  const s = summarizeAudit(ENTRIES, { denyOnly: true });
  assert.equal(s.total, 2);
  assert.equal(s.byVerdict.deny, 2);
  assert.equal(s.byVerdict.allow, 0);
});

test('summarizeAudit honors a context glob filter', () => {
  const s = summarizeAudit(ENTRIES, { contextGlob: '*prod*' });
  assert.equal(s.total, 2); // only the prod entries
  assert.equal(s.deniesByContext.prod, 2);
});

test('summarizeAudit honors a since cutoff (timestamp ms)', () => {
  const cutoff = Date.parse('2026-06-13T11:30:00Z');
  const s = summarizeAudit(ENTRIES, { sinceTs: cutoff });
  assert.equal(s.total, 2); // the 12:00 deny and 13:00 ask
});

test('summarizeAudit tolerates an empty list', () => {
  const s = summarizeAudit([], {});
  assert.equal(s.total, 0);
  assert.deepEqual(s.byVerdict, { allow: 0, ask: 0, deny: 0 });
  assert.deepEqual(s.topDenied, []);
});
