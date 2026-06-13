#!/usr/bin/env node
// /kube-guard doctor — validate config and sanity-check the install.
// Read-only: resolves the effective config, current context, leases, and
// surfaces validateConfig() warnings. Never mutates anything.
import { execFileSync } from 'node:child_process';
import { loadConfig, projectDir, validateConfig, readLeases, activeLeases } from './lib.mjs';
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

console.log('kube-guard doctor\n');
console.log(`node            : ${process.version}`);
console.log(`kubectl on PATH : ${run(['version', '--client']) ? 'yes' : 'NOT FOUND (current-context guard will be limited)'}`);

const current = run(['config', 'current-context']);
console.log(`current context : ${current || '(none resolved)'}`);
if (current) console.log(`  -> resolved level: ${resolveLevel(current, cfg, leases)}`);

console.log('\neffective config:');
console.log(`  defaultMode        : ${cfg.defaultMode || cfg.mode || 'strict'}`);
console.log(`  contextPolicies    : ${(cfg.contextPolicies || []).length} rule(s)`);
console.log(`  protectedContexts  : ${JSON.stringify(cfg.protectedContexts || [])}`);
console.log(`  protectedNamespaces: ${JSON.stringify(cfg.protectedNamespaces || [])}`);
console.log(`  allowExec / allowSecretRead: ${!!cfg.allowExec} / ${!!cfg.allowSecretRead}`);

console.log(`\nactive leases   : ${leases.length}`);
for (const l of leases) console.log(`  ${l.context} -> ${l.level}`);

const warnings = validateConfig(cfg);
console.log(`\nvalidation      : ${warnings.length ? `${warnings.length} warning(s)` : 'OK'}`);
for (const w of warnings) console.log(`  ⚠ ${w}`);

process.exit(0);
