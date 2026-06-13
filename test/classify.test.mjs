// Run: node --test   (zero dependencies — uses the built-in test runner)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, splitSegments, resourceKind } from '../scripts/classify.mjs';

const v = (cmd, cfg = {}, runtime = {}) => classify(cmd, cfg, runtime).verdict;

test('reads are allowed', () => {
  assert.equal(v('kubectl get pods'), 'allow');
  assert.equal(v('kubectl get pods -n kube-system'), 'allow'); // read on protected ns is fine
  assert.equal(v('kubectl describe deploy/web'), 'allow');
  assert.equal(v('kubectl logs pod-x -f'), 'allow');
  assert.equal(v('kubectl rollout status deploy/x'), 'allow');
  assert.equal(v('kubectl get secrets'), 'allow'); // names only
  assert.equal(v('helm list'), 'allow');
});

test('non-kubectl commands are allowed', () => {
  assert.equal(v('git status'), 'allow');
  assert.equal(v('ls && echo hi'), 'allow');
  assert.equal(v('npm test'), 'allow');
});

test('writes ask for confirmation', () => {
  assert.equal(v('kubectl apply -f deploy.yaml'), 'ask');
  assert.equal(v('kubectl scale deploy/x --replicas=0'), 'ask');
  assert.equal(v('kubectl rollout restart deploy/x'), 'ask');
  assert.equal(v('kubectl cordon node1'), 'ask');
  assert.equal(v('kubectl replace -f x.yaml'), 'ask');
  assert.equal(v('helm upgrade app ./chart'), 'ask');
  assert.equal(v('kubectl config use-context staging'), 'ask');
});

test('destructive verbs are denied (strict)', () => {
  assert.equal(v('kubectl delete pod x'), 'deny');
  assert.equal(v('kubectl delete ns prod'), 'deny');
  assert.equal(v('kubectl drain node1'), 'deny');
  assert.equal(v('kubectl taint nodes n1 k=v:NoSchedule'), 'deny');
  assert.equal(v('kubectl replace --force -f x.yaml'), 'deny');
  assert.equal(v('helm uninstall app'), 'deny');
  assert.equal(v('helm rollback app 1'), 'deny');
});

test('high-risk verbs are denied', () => {
  assert.equal(v('kubectl exec -it pod -- sh'), 'deny');
  assert.equal(v('kubectl run tmp --image=alpine -it -- sh'), 'deny');
  assert.equal(v('kubectl cp ns/pod:/etc/passwd ./x'), 'deny');
  assert.equal(v('kubectl port-forward svc/db 5432:5432'), 'deny');
  assert.equal(v('kubectl config view'), 'deny');
});

test('secret dumps are denied, name/wide/list are fine', () => {
  assert.equal(v('kubectl get secret s -o yaml'), 'deny');
  assert.equal(v('kubectl get secret s -o json'), 'deny');
  assert.equal(v('kubectl get secret s -o jsonpath={.data}'), 'deny');
  assert.equal(v('kubectl get -o yaml secret/foo'), 'deny');
  assert.equal(v('kubectl get secret s -o name'), 'allow');
});

test('chained commands take the strictest verdict', () => {
  assert.equal(v('cd /tmp && kubectl delete pod y'), 'deny');
  assert.equal(v('kubectl get pods; kubectl apply -f x.yaml'), 'ask');
  assert.equal(v('kubectl get pods && kubectl delete ns staging'), 'deny');
});

test('protected context/namespace escalates mutations to deny', () => {
  assert.equal(v('kubectl apply -f d.yaml --context prod'), 'deny');
  assert.equal(v('kubectl --context prod scale deploy/x --replicas=0'), 'deny');
  assert.equal(v('kubectl apply -f d.yaml'), 'ask'); // no context -> just ask
  // current context resolved at runtime:
  assert.equal(v('kubectl apply -f d.yaml', {}, { currentContext: 'my-prod-cluster' }), 'deny');
  assert.equal(v('kubectl apply -f d.yaml', {}, { currentContext: 'staging' }), 'ask');
  assert.equal(v('kubectl delete pod x -n production'), 'deny');
});

test('obfuscation fails closed', () => {
  assert.equal(v('eval "$(echo kubectl delete ns prod)"'), 'deny');
  assert.equal(v('echo kubectl delete ns prod | sh'), 'deny');
  assert.equal(v('bash -c "kubectl delete ns prod"'), 'deny');
  assert.equal(v('kubectl get pods | xargs kubectl delete pod'), 'deny');
  // PowerShell eval equivalents
  assert.equal(v('iex "kubectl delete ns prod"'), 'deny');
  assert.equal(v('Invoke-Expression "kubectl delete ns prod"'), 'deny');
  assert.equal(v('echo "kubectl delete ns prod" | iex'), 'deny');
});

test('unknown verbs fail closed to ask', () => {
  assert.equal(v('kubectl frobnicate widget'), 'ask');
  assert.equal(v('helm doSomethingNew app'), 'ask');
});

test('modes change strictness', () => {
  assert.equal(v('kubectl delete pod x', { mode: 'standard' }), 'ask');
  assert.equal(v('kubectl delete pod x -n prod', { mode: 'standard' }), 'deny'); // protected stays deny
  assert.equal(v('kubectl delete ns prod', { mode: 'audit' }), 'allow'); // observe-only
});

test('allow flags downgrade high-risk', () => {
  assert.equal(v('kubectl exec pod -- ls', { allowExec: true }), 'ask');
  assert.equal(v('kubectl get secret s -o yaml', { allowSecretRead: true }), 'ask');
});

test('reads never get a wide blast radius label', () => {
  const r = classify('kubectl get pods -n askonchat -l app=x -o wide');
  assert.equal(r.verdict, 'allow');
  assert.ok(!r.reasons.join(' ').toLowerCase().includes('wide'));
});

test('multi-command: write asks, reads stay clean', () => {
  const r = classify('kubectl scale deployment a -n a --replicas=2; kubectl get deployment a -n a; kubectl get pods -n a -l app=a -o wide');
  assert.equal(r.verdict, 'ask');
  assert.ok(!r.reasons.join(' ').toLowerCase().includes('read) with wide'));
});

test('quotes protect operators inside arguments', () => {
  const r = classify('kubectl annotate pod x note="a && b"');
  assert.equal(r.verdict, 'ask');
  assert.equal(r.segments.length, 1);
});

test('per-context policies pick the level by target context', () => {
  const cfg = {
    defaultMode: 'strict',
    protectedContexts: [],
    contextPolicies: [
      { match: ['*prod*', 'do-sfo3-*'], level: 'readonly' },
      { match: ['*stag*'], level: 'strict' },
      { match: ['kind-*', '*dev*'], level: 'audit' },
    ],
  };
  assert.equal(classify('kubectl apply -f x.yaml --context do-sfo3-pickrides', cfg).verdict, 'deny');
  assert.equal(classify('kubectl scale deploy/a --replicas=3 --context prod-eu', cfg).verdict, 'deny');
  assert.equal(classify('kubectl apply -f x.yaml --context staging', cfg).verdict, 'ask');
  assert.equal(classify('kubectl apply -f x.yaml --context kind-dev', cfg).verdict, 'allow');
  assert.equal(classify('kubectl delete pod p --context kind-dev', cfg).verdict, 'allow');
  assert.equal(classify('kubectl get pods --context kind-dev', cfg).verdict, 'allow');
});

test('defaultMode applies to unlisted contexts', () => {
  const cfg = { defaultMode: 'audit', protectedContexts: [], contextPolicies: [{ match: ['*prod*'], level: 'readonly' }] };
  assert.equal(classify('kubectl delete pod p --context whatever', cfg).verdict, 'allow');
  assert.equal(classify('kubectl delete pod p --context prod-1', cfg).verdict, 'deny');
});

test('use-context confirms entering a guarded cluster, free for dev', () => {
  const cfg = { protectedContexts: [], contextPolicies: [{ match: ['*prod*'], level: 'readonly' }, { match: ['kind-*'], level: 'audit' }] };
  assert.equal(classify('kubectl config use-context prod-eu', cfg).verdict, 'ask');
  assert.equal(classify('kubectl config use-context kind-dev', cfg).verdict, 'allow');
});

test('a lease temporarily relaxes a protected context, then destructive stays denied', () => {
  const cfg = { protectedContexts: [], contextPolicies: [{ match: ['*prod*'], level: 'readonly' }] };
  assert.equal(classify('kubectl scale deploy/a --replicas=3 --context prod-eu', cfg).verdict, 'deny');
  const leased = { leases: [{ context: 'prod-eu', level: 'strict' }] };
  assert.equal(classify('kubectl scale deploy/a --replicas=3 --context prod-eu', cfg, leased).verdict, 'ask');
  assert.equal(classify('kubectl delete deploy/a --context prod-eu', cfg, leased).verdict, 'deny');
});

test('splitSegments respects quotes', () => {
  assert.deepEqual(splitSegments('a && b ; c | d'), ['a', 'b', 'c', 'd']);
  assert.deepEqual(splitSegments('echo "a && b"'), ['echo "a && b"']);
});

// ---- issue #17: per-resource-kind rules (tighten-only) ---------------------
test('issue #17: resourceKind normalizes name/group/comma forms', () => {
  assert.equal(resourceKind('deploy/web'), 'deploy');
  assert.equal(resourceKind('deployment.apps'), 'deployment');
  assert.equal(resourceKind('Nodes'), 'nodes');
  assert.equal(resourceKind('--flag'), '');
  assert.equal(resourceKind(''), '');
});

test('issue #17: resourceRules tighten the verdict for matching kinds', () => {
  const cfg = {
    protectedContexts: [], protectedNamespaces: [], defaultMode: 'standard',
    resourceRules: [{ kinds: ['node', 'nodes', 'namespace', 'pvc', '*.cattle.io'], verbs: ['delete', 'drain', 'taint'], verdict: 'deny' }],
  };
  // standard normally ASKS destructive; the rule forces DENY for these kinds
  assert.equal(classify('kubectl delete node n1 --context dev', cfg).verdict, 'deny');
  assert.equal(classify('kubectl drain nodes/n1 --context dev', cfg).verdict, 'deny');
  // a non-matching kind keeps the level verdict (ask under standard)
  assert.equal(classify('kubectl delete pod p --context dev', cfg).verdict, 'ask');
});

test('issue #17: resourceRules only tighten, never loosen', () => {
  const cfg = {
    protectedContexts: [], defaultMode: 'strict',
    resourceRules: [{ kinds: ['cm', 'configmap'], verbs: ['*'], verdict: 'ask' }],
  };
  // strict deny must NOT be loosened to ask by a verdict:ask rule
  assert.equal(classify('kubectl delete cm x --context dev', cfg).verdict, 'deny');
});
