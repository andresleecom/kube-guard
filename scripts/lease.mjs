#!/usr/bin/env node
// The "context leash": temporarily relax a context's posture, then auto-revert.
//   node lease.mjs <context> [--minutes N | --once] [--level strict|standard|audit]
//   node lease.mjs --list
//   node lease.mjs --clear [context]
import { readLeases, writeLeases, activeLeases } from './lib.mjs';

const argv = process.argv.slice(2);
const now = Date.now();

function flag(name) {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  const next = argv[i + 1];
  return next && !next.startsWith('--') ? next : true;
}

if (argv.length === 0 || argv.includes('--list')) {
  const active = activeLeases(readLeases(), now);
  if (!active.length) {
    console.log('No active leases. Every context is at its normal posture.');
    process.exit(0);
  }
  console.log('Active leases (auto-revert when they end):');
  for (const l of active) {
    const left = l.expiresAt ? `${Math.max(0, Math.round((l.expiresAt - now) / 1000))}s left` : `${l.uses} command(s) left`;
    console.log(`  ${l.context}  ->  ${l.level}   (${left})`);
  }
  process.exit(0);
}

if (argv.includes('--clear')) {
  const ctx = flag('--clear');
  if (typeof ctx === 'string') {
    writeLeases(readLeases().filter((l) => l.context !== ctx));
    console.log(`Cleared lease for ${ctx}.`);
  } else {
    writeLeases([]);
    console.log('Cleared all leases.');
  }
  process.exit(0);
}

const context = argv.find((a) => !a.startsWith('--'));
if (!context) {
  console.log('usage: node lease.mjs <context> [--minutes N | --once] [--level strict|standard|audit]');
  process.exit(0);
}

const lvl = flag('--level');
const level = typeof lvl === 'string' ? lvl : 'strict';
const once = argv.includes('--once');
const minutes = Number(flag('--minutes')) > 0 ? Number(flag('--minutes')) : 5;

const lease = { context, level, createdAt: now };
if (once) lease.uses = 1;
else lease.expiresAt = now + minutes * 60000;

const leases = readLeases().filter((l) => l.context !== context);
leases.push(lease);
writeLeases(leases);

const span = once ? 'the next 1 command' : `${minutes} min`;
console.log(`Leased ${context} -> ${level} for ${span}. It auto-reverts to the normal posture afterward.`);
