'use strict';
// Supply chain tests

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const ALLOWED = [/^dist\//, /^src\//, /^README\.md$/, /^LICENSE$/, /^CHANGELOG\.md$/, /^SECURITY\.md$/, /^package\.json$/];
const MAX_BYTES = 200 * 1024;


describe('manifest', () => {
  test('declared entry points exist', () => {
    for (const rel of [pkg.main, pkg.types, pkg.exports['.'].require, pkg.exports['.'].types]) {
      assert.ok(fs.existsSync(path.join(ROOT, rel)), `${rel} is declared but missing`);
    }
  });
  test('no install-time lifecycle scripts', () => {
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
      assert.equal(pkg.scripts[hook], undefined, `${hook} runs code on every consumer install`);
    }
  });
  test('npm test is wired to a real suite', () => {
    assert.ok(pkg.scripts.test && !/exit 1/.test(pkg.scripts.test));
  });
  test('runtime dependencies are exactly pinned', () => {
    for (const [name, range] of Object.entries(pkg.dependencies)) {
      assert.ok(/^\d+\.\d+\.\d+$/.test(range), `${name}@${range} is a range, not a pin`);
    }
  });
  test('engines declares a supported Node range', () => {
    assert.ok(pkg.engines && pkg.engines.node);
  });
});

describe('dependency tree', () => {
  const lock = JSON.parse(fs.readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));
  const entries = Object.entries(lock.packages).filter(([k]) => k);

  test('no package in the tree has an install script', () => {
    const scripted = entries.filter(([, v]) => v.hasInstallScript).map(([k]) => k);
    assert.deepEqual(scripted, [], 'install scripts execute code on npm ci and on every workstation');
  });
  test('every resolved URL points at the public registry', () => {
    const foreign = entries.filter(([, v]) => v.resolved && !v.resolved.startsWith('https://registry.npmjs.org/'));
    assert.deepEqual(foreign.map(([k]) => k), []);
  });
  test('the production tree is one package', () => {
    const prod = entries.filter(([, v]) => !v.dev);
    assert.ok(prod.length <= 1, `production tree has ${prod.length} packages: ${prod.map(([k]) => k).join(', ')}`);
  });
});
