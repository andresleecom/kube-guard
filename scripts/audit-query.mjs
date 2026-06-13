#!/usr/bin/env node
// /kube-guard summarize — roll up the (already-redacted) audit log. Read-only.
// Usage: node audit-query.mjs [--since 24h] [--deny-only] [--context <glob>] [--json]
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { projectDir } from './lib.mjs';
import { summarizeAudit } from './audit.mjs';

const argv = process.argv.slice(2);
function flag(name) {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  const next = argv[i + 1];
  return next && !next.startsWith('--') ? next : true;
}

// Parse a duration like 30m / 24h / 7d into milliseconds.
function durationMs(s) {
  const m = /^(\d+)\s*([smhd])$/.exec(String(s || '').trim());
  if (!m) return null;
  const n = Number(m[1]);
  return n * { s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[m[2]];
}

const opts = {};
const since = flag('--since');
if (typeof since === 'string') {
  const ms = durationMs(since);
  if (ms != null) opts.sinceTs = Date.now() - ms;
}
if (argv.includes('--deny-only')) opts.denyOnly = true;
const ctx = flag('--context');
if (typeof ctx === 'string') opts.contextGlob = ctx;

const file = join(projectDir({}), '.claude', 'kube-guard', 'audit.jsonl');
const entries = [];
if (existsSync(file)) {
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      entries.push(JSON.parse(line));
    } catch {
      /* skip malformed line */
    }
  }
}

const s = summarizeAudit(entries, opts);

if (argv.includes('--json')) {
  console.log(JSON.stringify(s, null, 2));
  process.exit(0);
}

if (!existsSync(file)) {
  console.log('No audit log yet (.claude/kube-guard/audit.jsonl). Run some kubectl/helm commands first.');
  process.exit(0);
}

console.log(`kube-guard audit summary  (${s.total} decision(s)${since ? `, last ${since}` : ''}${opts.denyOnly ? ', deny-only' : ''}${opts.contextGlob ? `, context ${opts.contextGlob}` : ''})\n`);
console.log(`verdicts : allow ${s.byVerdict.allow} · ask ${s.byVerdict.ask} · deny ${s.byVerdict.deny}`);
const klasses = Object.entries(s.byKlass).sort((a, b) => b[1] - a[1]);
if (klasses.length) console.log(`classes  : ${klasses.map(([k, n]) => `${k} ${n}`).join(' · ')}`);

const denyCtx = Object.entries(s.deniesByContext).sort((a, b) => b[1] - a[1]);
if (denyCtx.length) {
  console.log('\ndenies by context:');
  for (const [c, n] of denyCtx) console.log(`  ${c}  ${n}`);
}
if (s.topDenied.length) {
  console.log('\ntop denied commands:');
  for (const d of s.topDenied) console.log(`  ${d.count}x  ${d.command}`);
}
process.exit(0);
