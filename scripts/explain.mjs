#!/usr/bin/env node
// Dry-run a command through the classifier without executing it.
// Usage: node explain.mjs "kubectl delete ns prod"
import { classify } from './classify.mjs';

const cmd = process.argv.slice(2).join(' ');
if (!cmd) {
  console.log('usage: node explain.mjs "<command>"');
  process.exit(0);
}
const r = classify(cmd);
console.log(`verdict : ${r.verdict}`);
console.log(`class   : ${r.klass}`);
console.log(`reasons : ${r.reasons.join('; ')}`);
if (r.segments.length) {
  console.log('segments:');
  for (const s of r.segments) {
    console.log(`  - ${s.verb ?? '?'} [${s.klass}] -> ${s.verdict} (ctx=${s.context ?? '?'}, ns=${s.namespace ?? '?'})`);
  }
}
console.log('\nnote: run without live cluster context; the real hook also resolves your current kube-context.');
