// Run: node --test   (zero dependencies — uses the built-in test runner)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, splitSegments, decidingSegment, suggestAlternative, resourceKind } from '../scripts/classify.mjs';

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

// ---- issue #1: decide kubectl/helm relevance AFTER tokenization ------------
test('issue #1: intra-word quoting cannot hide the tool name (fail closed)', () => {
  assert.equal(v("k'ubectl' delete ns prod"), 'deny');
  assert.equal(v("kube'ctl' delete ns prod"), 'deny');
  assert.equal(v('k"ubectl" delete ns prod'), 'deny');
  assert.equal(v("h'elm' uninstall myrelease"), 'deny');
  assert.equal(v("k'ubectl' --context=production delete ns foo"), 'deny');
  assert.equal(v("k'ubectl' get pods"), 'allow'); // a quoted read is still a read
});

test('issue #1: obfuscation with intra-word quoting still fails closed', () => {
  assert.equal(v(`eval "k'ubectl' delete ns prod"`), 'deny');
  assert.equal(v(`bash -c "k'ubectl' delete ns prod"`), 'deny');
});

test('issue #1: merely mentioning kubectl/helm as text is allowed (no invocation)', () => {
  assert.equal(v(`git commit -m 'fix kubectl helm parsing'`), 'allow');
  assert.equal(v('echo "run kubectl delete ns prod"'), 'allow');
  assert.equal(v('echo kubectl delete ns prod'), 'allow'); // echo is a benign leader
  assert.equal(v('grep kubectl deploy.sh'), 'allow');
});

test('issue #1: which / command -v kubectl (the prereq check) are allowed', () => {
  assert.equal(v('which kubectl'), 'allow');
  assert.equal(v('command -v kubectl'), 'allow');
  assert.equal(v('type kubectl'), 'allow');
});

test('issue #1: unrecognized wrappers around kubectl fail closed', () => {
  assert.equal(v('timeout 5 kubectl delete ns prod'), 'deny');
  assert.equal(v('parallel kubectl delete pod ::: a b'), 'deny');
  // a recognized exec wrapper still classifies the REAL verb it runs:
  assert.equal(v('command kubectl delete ns prod'), 'deny');
  assert.equal(v('sudo kubectl delete ns prod'), 'deny');
});

// ---- issue #2: harden secret-dump detection -------------------------------
test('issue #2: a stuck -o flag does not evade secret-dump detection', () => {
  assert.equal(v('kubectl get secret x -oyaml'), 'deny');
  assert.equal(v('kubectl get secret x -ojson'), 'deny');
  assert.equal(v('kubectl get secret x -o=yaml'), 'deny');
  assert.equal(v('kubectl get secret x -o name'), 'allow'); // names only still fine
  assert.equal(v('kubectl get secret x -owide'), 'allow');
});

test('issue #2: comma-joined resource lists are caught regardless of order', () => {
  assert.equal(v('kubectl get configmaps,secrets -o yaml'), 'deny');
  assert.equal(v('kubectl get secrets,configmaps -o yaml'), 'deny');
  assert.equal(v('kubectl get cm,secret -o json'), 'deny');
  assert.equal(v('kubectl get pods,deploys -o yaml'), 'allow'); // no secrets in the list
});

test('issue #2: fully-qualified secret resource names are caught', () => {
  assert.equal(v('kubectl get secret.v1.core/db -o yaml'), 'deny');
  assert.equal(v('kubectl get secrets.v1. -o json'), 'deny');
});

test('issue #2: go-template / --template secret dumps are caught (no -o flag)', () => {
  assert.equal(v('kubectl get secret db --template={{.data.password}}'), 'deny');
  assert.equal(v('kubectl get secret db --go-template={{.data}}'), 'deny');
  assert.equal(v('kubectl get secret db --go-template-file ./x.tmpl'), 'deny');
});

test('issue #2: helm get manifest/values/all expose release secrets', () => {
  assert.equal(v('helm get manifest myrel'), 'deny');
  assert.equal(v('helm get values myrel --all'), 'deny');
  assert.equal(v('helm get all myrel'), 'deny');
  assert.equal(v('helm get notes myrel'), 'allow'); // notes are not secrets
  assert.equal(v('helm list'), 'allow'); // unchanged
});

test('issue #2: allowSecretRead downgrades the new secret paths to ask', () => {
  assert.equal(v('kubectl get secret x -oyaml', { allowSecretRead: true }), 'ask');
  assert.equal(v('helm get values myrel', { allowSecretRead: true }), 'ask');
});

// ---- issue #3: RBAC escalation and apply --prune --------------------------
test('issue #3: kubectl auth reconcile is a privilege-granting write, not a read', () => {
  assert.equal(v('kubectl auth reconcile -f rbac.yaml'), 'deny'); // HIGH_RISK
  assert.equal(v('kubectl auth can-i create pods'), 'allow'); // read
  assert.equal(v('kubectl auth whoami'), 'allow'); // read
});

test('issue #3: create/apply of RBAC roles & bindings is escalated', () => {
  assert.equal(v('kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=x'), 'deny');
  assert.equal(v('kubectl create rolebinding rb --role=admin --user=x'), 'deny');
  assert.equal(v('kubectl create clusterrole cr --verb=* --resource=*'), 'deny');
  assert.equal(v('kubectl create configmap cm --from-literal=a=b'), 'ask'); // ordinary write unaffected
});

test('issue #3: apply --prune is destructive (it deletes live objects)', () => {
  assert.equal(v('kubectl apply --prune -f . -l app=x'), 'deny');
  assert.equal(v('kubectl apply --prune --all -f .'), 'deny');
  assert.equal(v('kubectl apply -f deploy.yaml'), 'ask'); // plain apply still just asks
});

// ---- issue #4: invalid levels must never weaken the guard -----------------
test("issue #4: a typo'd contextPolicy level coerces to readonly (write stays denied)", () => {
  const cfg = { protectedContexts: [], contextPolicies: [{ match: ['*prod*'], level: 'readonyl' }] };
  // WRITE distinguishes readonly (deny) from the buggy fall-through (ask):
  assert.equal(classify('kubectl scale deploy/a --replicas=3 --context prod-eu', cfg).verdict, 'deny');
  assert.equal(classify('kubectl apply -f x.yaml --context prod-eu', cfg).verdict, 'deny');
});

test("issue #4: a typo'd lease level coerces to strict (destructive stays denied)", () => {
  const cfg = { protectedContexts: [], contextPolicies: [{ match: ['*prod*'], level: 'readonly' }] };
  const leased = { leases: [{ context: 'prod-eu', level: 'auditt' }] }; // typo for 'audit'
  assert.equal(classify('kubectl scale deploy/a --replicas=3 --context prod-eu', cfg, leased).verdict, 'ask'); // write asks
  assert.equal(classify('kubectl delete deploy/a --context prod-eu', cfg, leased).verdict, 'deny'); // destructive denied
});

test("issue #4: a typo'd defaultMode coerces to strict", () => {
  const cfg = { protectedContexts: [], contextPolicies: [], defaultMode: 'striict' };
  assert.equal(classify('kubectl delete pod x --context dev1', cfg).verdict, 'deny'); // strict denies destructive
});

// ---- issue #6: shell-aware parser (PowerShell + splitSegments edge cases) --
test('issue #6: PowerShell backtick line-continuation is no longer denied', () => {
  assert.equal(v('kubectl get pods `\n  -n default'), 'allow');
  assert.equal(v('kubectl get pods `'), 'allow'); // trailing continuation, still a read
});

test('issue #6: a stray backtick cannot swallow a separator (no latent bypass)', () => {
  assert.equal(v('a x=`; kubectl delete ns prod'), 'deny'); // ';' must still split
  assert.deepEqual(splitSegments('a x=`; kubectl delete ns prod'), ['a x=`', 'kubectl delete ns prod']);
});

test('issue #6: bash backtick command-substitution around kubectl still fails closed', () => {
  assert.equal(v('echo `kubectl delete ns prod`'), 'deny');
  assert.equal(v('`kubectl delete ns prod`'), 'deny');
});

test('issue #6: a # comment is ignored (and cannot smuggle a destructive verb)', () => {
  assert.equal(v('kubectl get pods # kubectl delete ns prod'), 'allow');
  assert.equal(v('kubectl delete ns prod # please'), 'deny'); // verb before the comment still counts
  assert.deepEqual(splitSegments('kubectl get pods # kubectl delete ns prod'), ['kubectl get pods']);
});

test('issue #6: fd-dup redirect (2>&1) is not split as a background separator', () => {
  const r = classify('kubectl get pods 2>&1');
  assert.equal(r.verdict, 'allow');
  assert.equal(r.segments.length, 1);
  assert.deepEqual(splitSegments('kubectl get pods 2>&1'), ['kubectl get pods 2>&1']);
  // a real background '&' still splits:
  assert.deepEqual(splitSegments('kubectl get pods & echo done'), ['kubectl get pods', 'echo done']);
});

// ---- issue #9: obfuscation must stay fail-closed even under audit ----------
test('issue #9: obfuscation never auto-allows under audit (at least ask)', () => {
  // audit normally allows everything, but obfuscation is unverifiable -> ask
  assert.equal(v('eval "kubectl delete ns prod"', { mode: 'audit' }), 'ask');
  assert.equal(v('echo kubectl delete ns prod | sh', { mode: 'audit' }), 'ask');
});

test('issue #9: obfuscation against a protected current context is denied even under audit', () => {
  // the obfuscated segment consults the live context: prod -> readonly -> deny
  assert.equal(v('eval "kubectl delete ns prod"', { mode: 'audit' }, { currentContext: 'my-prod-cluster' }), 'deny');
});

test('issue #9: obfuscation verdicts unchanged for strict/standard', () => {
  assert.equal(v('eval "kubectl delete ns prod"'), 'deny'); // strict default
  assert.equal(v('eval "kubectl delete ns prod"', { mode: 'standard' }), 'ask'); // standard -> ask
});

// ---- issue #10: audit attribution ------------------------------------------
test('issue #10: decidingSegment is the segment that set the verdict (not segments[0])', () => {
  const cfg = { protectedContexts: [], contextPolicies: [{ match: ['*prod*'], level: 'readonly' }, { match: ['kind-*'], level: 'audit' }] };
  const r = classify('kubectl get pods --context kind-dev && kubectl delete pod x --context prod-eu', cfg);
  assert.equal(r.verdict, 'deny');
  const d = decidingSegment(r);
  assert.equal(d.context, 'prod-eu'); // the deciding (denied) segment, not kind-dev (segments[0])
  assert.equal(d.verdict, 'deny');
});

test('issue #10: decidingSegment falls back to the first segment and tolerates empty', () => {
  const r = classify('kubectl get pods'); // single allow segment
  assert.equal(decidingSegment(r).verdict, 'allow');
  assert.equal(decidingSegment({ verdict: 'allow', segments: [] }), null);
});

// ---- issue #13: --dry-run awareness ----------------------------------------
test('issue #13: --dry-run downgrades a mutation to a safe preview (READ)', () => {
  assert.equal(v('kubectl apply -f x.yaml --dry-run=server'), 'allow');
  assert.equal(v('kubectl delete pod x --dry-run=client'), 'allow');
  assert.equal(v('kubectl scale deploy/x --replicas=0 --dry-run=server'), 'allow');
  assert.equal(v('kubectl delete ns prod --dry-run=server --context prod'), 'allow'); // preview is safe even on prod
  assert.equal(v('helm upgrade app ./chart --dry-run'), 'allow');
  assert.equal(v('helm uninstall app --dry-run'), 'allow');
});

test('issue #13: --dry-run=none really applies (no downgrade)', () => {
  assert.equal(v('kubectl apply -f x.yaml --dry-run=none'), 'ask');
  assert.equal(v('kubectl delete pod x --dry-run=none'), 'deny');
});

test('issue #13: dry-run never downgrades high-risk (exec/secret have no dry-run)', () => {
  assert.equal(v('kubectl get secret s -o yaml --dry-run=client'), 'deny'); // still a secret dump
  assert.equal(v('kubectl run tmp --image=alpine --dry-run=client', { allowExec: false }), 'deny');
});

// ---- issue #14: actionable "why denied + safe alternative" -----------------
test('issue #14: suggestAlternative gives an actionable tip per case', () => {
  assert.match(suggestAlternative({ klass: 'DESTRUCTIVE', verb: 'delete', level: 'strict' }), /dry-run|klease|scale/i);
  assert.match(suggestAlternative({ klass: 'WRITE', verb: 'apply', level: 'readonly' }), /klease|non-prod/i);
  assert.match(suggestAlternative({ klass: 'WRITE', verb: 'apply', level: 'strict' }), /dry-run|diff/i);
  assert.match(suggestAlternative({ klass: 'HIGH_RISK', verb: 'get' }), /-o name|allowSecretRead/i);
  assert.match(suggestAlternative({ klass: 'HIGH_RISK', verb: 'exec' }), /allowExec|read/i);
  assert.match(suggestAlternative({ klass: 'OBFUSCATED' }), /directly|classif/i);
  assert.equal(suggestAlternative({ klass: 'READ', verb: 'get' }), ''); // nothing to suggest for allows
  assert.equal(suggestAlternative(null), '');
});

// ---- issue #16: per-namespace policies, composed strictest with context ----
test('issue #16: a namespace policy composes with the context level (strictest wins)', () => {
  const cfg = {
    protectedContexts: [], protectedNamespaces: [],
    contextPolicies: [{ match: ['kind-*'], level: 'audit' }],
    namespacePolicies: [{ match: ['prod', '*-prod'], level: 'readonly' }],
  };
  // audit context but readonly namespace -> readonly wins -> deny
  assert.equal(classify('kubectl delete pod x -n prod --context kind-dev', cfg).verdict, 'deny');
  assert.equal(classify('kubectl apply -f x -n prod --context kind-dev', cfg).verdict, 'deny');
  // dev namespace imposes nothing -> context audit applies -> allow
  assert.equal(classify('kubectl delete pod x -n dev --context kind-dev', cfg).verdict, 'allow');
});

test('issue #16: a protected namespace is guarded even under an audit context', () => {
  const cfg = { protectedContexts: [], contextPolicies: [{ match: ['kind-*'], level: 'audit' }], protectedNamespaces: ['kube-system'] };
  assert.equal(classify('kubectl delete pod x -n kube-system --context kind-dev', cfg).verdict, 'deny');
  assert.equal(classify('kubectl get pods -n kube-system --context kind-dev', cfg).verdict, 'allow'); // reads still fine
});

test('issue #16: an unlisted namespace imposes nothing (context level applies)', () => {
  const cfg = { protectedContexts: [], protectedNamespaces: [], contextPolicies: [{ match: ['*prod*'], level: 'readonly' }], namespacePolicies: [] };
  assert.equal(classify('kubectl delete pod x -n whatever --context prod-eu', cfg).verdict, 'deny'); // context readonly
  assert.equal(classify('kubectl apply -f x -n whatever --context kind-dev', cfg).verdict, 'ask'); // kind-dev unlisted -> defaultMode strict
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
