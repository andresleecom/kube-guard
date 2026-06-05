// Run: node --test   (zero dependencies — uses the built-in test runner)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, splitSegments } from '../scripts/classify.mjs';

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

test('quotes protect operators inside arguments', () => {
  const r = classify('kubectl annotate pod x note="a && b"');
  assert.equal(r.verdict, 'ask');
  assert.equal(r.segments.length, 1);
});

test('splitSegments respects quotes', () => {
  assert.deepEqual(splitSegments('a && b ; c | d'), ['a', 'b', 'c', 'd']);
  assert.deepEqual(splitSegments('echo "a && b"'), ['echo "a && b"']);
});
