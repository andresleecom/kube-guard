// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #5: runKubectl() centralizes kubectl invocation and resolves the binary
// robustly on Windows (.exe, then a cmd.exe shell fallback for .cmd/.bat shims).
// This test pins the FAIL-SAFE contract (it must never throw and always returns
// a string), which holds whether or not kubectl is installed. Real-cluster
// resolution is verified empirically (see the PR), not in CI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runKubectl } from '../scripts/lib.mjs';

test('runKubectl never throws and always returns a string', () => {
  // kubectl missing -> '' ; kubectl present but bad subcommand -> '' . Either way: a string.
  const out = runKubectl(['__definitely_not_a_real_subcommand__']);
  assert.equal(typeof out, 'string');
});

test('runKubectl tolerates an empty/garbage args array without throwing', () => {
  assert.equal(typeof runKubectl([]), 'string');
});
