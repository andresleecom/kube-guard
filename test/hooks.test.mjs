// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #12: the actual hook entry points (guard.mjs/notice.mjs) and the CLIs
// (explain/contexts/lease) had ZERO tests. Drive them as subprocesses with
// crafted stdin/args. Isolated via temp HOME/USERPROFILE + CLAUDE_PROJECT_DIR
// so a test never touches the user's real leases or audit log.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const script = (name) => fileURLToPath(new URL(`../scripts/${name}`, import.meta.url));

// Run a script in an isolated sandbox; returns { stdout, status }. Never throws
// on a non-zero exit (kube-guard scripts always exit 0, but be defensive).
function run(name, { args = [], input = '' } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'kg-home-'));
  const proj = mkdtempSync(join(tmpdir(), 'kg-proj-'));
  try {
    const env = { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj };
    const stdout = execFileSync(process.execPath, [script(name), ...args], { input, env, encoding: 'utf8' });
    return { stdout, status: 0 };
  } catch (e) {
    return { stdout: (e.stdout || '').toString(), status: e.status ?? 1 };
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(proj, { recursive: true, force: true });
  }
}

const hookInput = (command, tool_response) => JSON.stringify({ tool_input: { command }, tool_response });

test('guard.mjs denies a destructive command', () => {
  const { stdout } = run('guard.mjs', { input: hookInput('kubectl delete ns prod') });
  assert.match(stdout, /"permissionDecision":"deny"/);
});

test('guard.mjs allows a read (emits nothing)', () => {
  const { stdout } = run('guard.mjs', { input: hookInput('kubectl get pods') });
  assert.equal(stdout.trim(), '');
});

test('guard.mjs ignores non-kubectl commands and malformed stdin (exit 0, no output)', () => {
  assert.equal(run('guard.mjs', { input: hookInput('git status') }).stdout.trim(), '');
  assert.equal(run('guard.mjs', { input: 'not json{' }).stdout.trim(), '');
  assert.equal(run('guard.mjs', { input: '' }).stdout.trim(), '');
});

test('notice.mjs warns when kubectl output looks like secrets', () => {
  const secretish = '-----BEGIN PRIVATE KEY-----\nMIIBmabc\n-----END PRIVATE KEY-----';
  const { stdout } = run('notice.mjs', { input: hookInput('kubectl get secret x -o yaml', { stdout: secretish }) });
  assert.match(stdout, /additionalContext/);
});

test('notice.mjs stays silent for non-k8s commands and clean output', () => {
  assert.equal(run('notice.mjs', { input: hookInput('ls -la', { stdout: 'file1 file2' }) }).stdout.trim(), '');
  assert.equal(run('notice.mjs', { input: hookInput('kubectl get pods', { stdout: 'no secrets here' }) }).stdout.trim(), '');
});

test('explain.mjs prints a verdict line and the right class', () => {
  const { stdout } = run('explain.mjs', { args: ['kubectl delete ns prod'] });
  assert.match(stdout, /verdict\s*:\s*deny/);
  assert.match(stdout, /DESTRUCTIVE/);
});

test('contexts.mjs runs without crashing (smoke)', () => {
  const { status, stdout } = run('contexts.mjs');
  assert.equal(status, 0);
  assert.ok(stdout.length > 0); // either a context list or "No contexts found"
});

test('lease.mjs create -> list -> clear round-trips in an isolated HOME', () => {
  // share one HOME across the calls by running them in a single sandbox
  const home = mkdtempSync(join(tmpdir(), 'kg-home-'));
  try {
    const env = { ...process.env, HOME: home, USERPROFILE: home };
    const sh = (args) => execFileSync(process.execPath, [script('lease.mjs'), ...args], { env, encoding: 'utf8' });
    assert.match(sh(['--list']), /No active leases/);
    assert.match(sh(['my-prod-cluster', '--once', '--level', 'strict']), /Leased/);
    assert.match(sh(['--list']), /my-prod-cluster/);
    assert.match(sh(['--clear', 'my-prod-cluster']), /Cleared/);
    assert.match(sh(['--list']), /No active leases/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
