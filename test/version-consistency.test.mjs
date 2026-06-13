// Run: node --test   (zero dependencies — uses the built-in test runner)
// Issue #18: the version must not drift across the surfaces that advertise it.
// This pins plugin.json == marketplace.json == README badge == CHANGELOG top.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');

test('version is consistent across plugin.json, marketplace.json, README badge and CHANGELOG', () => {
  const plugin = JSON.parse(read('.claude-plugin/plugin.json')).version;
  const marketplace = JSON.parse(read('.claude-plugin/marketplace.json')).plugins[0].version;
  const badge = read('README.md').match(/badge\/version-([0-9]+\.[0-9]+\.[0-9]+)-/)?.[1];
  const changelog = read('CHANGELOG.md').match(/##\s*\[([0-9]+\.[0-9]+\.[0-9]+)\]/)?.[1];

  assert.ok(/^\d+\.\d+\.\d+$/.test(plugin), `plugin.json version looks wrong: ${plugin}`);
  assert.equal(marketplace, plugin, 'marketplace.json plugins[0].version must match plugin.json');
  assert.equal(badge, plugin, 'README version badge must match plugin.json');
  assert.equal(changelog, plugin, 'CHANGELOG top version must match plugin.json');
});
