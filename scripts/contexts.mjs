#!/usr/bin/env node
// List kube-contexts with the kube-guard level that applies to each.
import { execFileSync } from 'node:child_process';
import { loadConfig, projectDir, readLeases, activeLeases } from './lib.mjs';
import { resolveLevel } from './classify.mjs';

const run = (args) => {
  try {
    return execFileSync('kubectl', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 }).trim();
  } catch {
    return '';
  }
};

const cfg = loadConfig(projectDir({}));
const leases = activeLeases(readLeases(), Date.now());
const current = run(['config', 'current-context']);
const names = run(['config', 'get-contexts', '-o', 'name']).split(/\r?\n/).filter(Boolean);

const DESC = {
  readonly: 'readonly  (mutations denied)',
  strict: 'strict    (writes ask, destructive denied)',
  standard: 'standard  (destructive asks)',
  audit: 'audit     (allow + log)',
};

if (!names.length) {
  console.log('No contexts found (is kubectl configured?).');
  process.exit(0);
}

console.log('Contexts (current marked with *):');
for (const n of names) {
  const lvl = resolveLevel(n, cfg, leases);
  const leased = leases.find((l) => l.context === n) ? '   [leased]' : '';
  console.log(`${n === current ? '* ' : '  '}${n}  ->  ${DESC[lvl] || lvl}${leased}`);
}
