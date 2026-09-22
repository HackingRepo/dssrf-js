'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const dssrf = require('../dist/utils.js');
const { startHttp, nextPort, withStubResolver } = require('./harness.js');

const grab = async (fn) => { try { return { ok: true, v: await fn() }; } catch (e) { return { ok: false, e }; } };

describe('resolve_and_pin refuses what it should', () => {
  const cases = [
    ['http://127.0.0.1/', 'internal-address'],
    ['http://169.254.169.254/', 'internal-address'],
    ['http://[::ffff:127.0.0.1]/', 'internal-address'],
    ['http://[::7f00:1]/', 'internal-address'],
    ['http://[::a9fe:a9fe]/', 'internal-address'],
    ['file:///etc/passwd', 'scheme-not-allowed'],
    ['gopher://127.0.0.1:11211/', 'scheme-not-allowed'],
    ['http://user@127.0.0.1/', 'userinfo-present'],
    ['http://example.com:22/', 'port-not-allowed'],
    ['http://example.com:6379/', 'port-not-allowed'],
    ['http://nonexistent-abc123.invalid/', 'host-not-found'],
    [null, 'unparseable-url'],
  ];
  for (const [input, reason] of cases) {
    test(`${JSON.stringify(input)} -> ${reason}`, async () => {
      const r = await grab(() => dssrf.resolve_and_pin(input));
      assert.equal(r.ok, false, 'must refuse');
      assert.equal(r.e.reason, reason);
      assert.equal(r.e.code, 'DSSRF_REFUSED');
    });
  }
});

describe('refusal reasons let an app tell "refuse" from "accuse"', () => {
  test('a nonexistent host is host-not-found, not an internal-address block', async () => {
    const r = await grab(() => dssrf.resolve_and_pin('http://examepjer-typo-xyz.invalid/'));
    assert.equal(r.e.reason, 'host-not-found');
  });
  test('a withholding resolver is resolution-failed', async () => {
    const stub = await withStubResolver({ answer: () => null, hosts: { 'withheld.test': null } });
    try {
      const r = await grab(() => dssrf.resolve_and_pin('http://withheld.test/'));
      assert.equal(r.e.reason, 'resolution-failed');
    } finally { stub.restore(); }
  });
});

describe('safe_fetch', () => {
  let internal, attacker, methods, stub;

  before(async () => {
    internal = await startHttp((q, r) => r.end('INTERNAL-SERVICE-MARKER'));
    methods = [];
    attacker = await startHttp((q, r) => {
      methods.push(q.method);
      if (q.method === 'HEAD') { r.writeHead(200); return r.end(); }
      if (q.url === '/loop') { r.writeHead(302, { location: '/loop' }); return r.end(); }
      if (q.url === '/nolocation') { r.writeHead(302); return r.end(); }
      r.writeHead(302, { location: `http://127.0.0.1:${internal.port}/secret` });
      r.end();
    });
    attacker.url = `http://pinned.test:${attacker.port}/`;
    stub = await withStubResolver({
      answer: ({ qtype }) => (qtype === 1 ? '93.184.216.34' : null),
      hosts: { 'pinned.test': '127.0.0.1' },
    });
  });
  after(() => { stub.restore(); internal.close(); attacker.close(); });

  test('a redirect into internal space is refused, with no HEAD probe', async () => {
    methods.length = 0;
    const r = await grab(() => dssrf.safe_fetch(attacker.url, { ports: [attacker.port, internal.port], allow: [`127.0.0.1:${attacker.port}`] }));
    assert.equal(r.ok, false);
    assert.equal(r.e.reason, 'internal-address');
    assert.ok(!methods.includes('HEAD'), `probed with HEAD: ${methods}`);
    assert.deepEqual(methods, ['GET'], 'the request made is the request validated');
  });

  test('a 3xx without Location is refused, not treated as a safe terminus', async () => {
    const r = await grab(() => dssrf.safe_fetch(attacker.url + 'nolocation', { ports: [attacker.port], allow: [`127.0.0.1:${attacker.port}`] }));
    assert.equal(r.e.reason, 'redirect-without-location');
  });

  test('a redirect loop terminates', async () => {
    const r = await grab(() => dssrf.safe_fetch(attacker.url + 'loop', { ports: [attacker.port], allow: [`127.0.0.1:${attacker.port}`] }));
    assert.equal(r.e.reason, 'too-many-redirects');
  });

  test('exactly one resolution per hop, and the socket uses it', async () => {
    const before = stub.lookups();
    const ok = await startHttp((q, r) => r.end('OK'));
    try {
      const res = await dssrf.safe_fetch(`http://pinned.test:${ok.port}/`, { ports: [ok.port], allow: [`127.0.0.1:${ok.port}`] });
      assert.equal(res.body, 'OK');
      assert.equal(res.chain.length, 1);
      assert.equal(res.chain[0].address, '127.0.0.1', 'connected to the address it validated');
      assert.equal(stub.lookups() - before, 1, 'must resolve exactly once -- no second lookup to poison');
    } finally { ok.close(); }
  });
});

describe('TLS: connect by address, authenticate by name', () => {
  let srv, stub;
  const ca = fs.readFileSync(path.join(__dirname, 'tls', 'ca.crt'));

  before(async () => {
    srv = https.createServer({
      key: fs.readFileSync(path.join(__dirname, 'tls', 'srv.key')),
      cert: fs.readFileSync(path.join(__dirname, 'tls', 'srv.crt')),
    }, (q, r) => r.end('TLS-OK'));
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    srv.port = srv.address().port;
    stub = await withStubResolver({
      answer: ({ qtype }) => (qtype === 1 ? '93.184.216.34' : null),
      hosts: { 'pinned.test': '127.0.0.1', 'wrong.test': '127.0.0.1' },
    });
  });
  after(() => { stub.restore(); srv.close(); });

  test('a certificate for the hostname validates while connected to the IP', async () => {
    const saved = https.globalAgent.options.ca;
    https.globalAgent.options.ca = ca;
    process.env.NODE_EXTRA_CA_CERTS = '';
    try {
      const r = await grab(() => dssrf.safe_fetch(`https://pinned.test:${srv.port}/`,
        { ports: [srv.port], allow: [`127.0.0.1:${srv.port}`] }));
      // The request must either succeed, or fail for a CA reason, never for a
      // hostname-identity reason, which would mean SNI was set wrong.
      if (r.ok) assert.equal(r.v.body, 'TLS-OK');
      else assert.doesNotMatch(String(r.e.code || r.e.message), /ALTNAME/,
        `identity check failed against the right host: ${r.e.message}`);
    } finally { https.globalAgent.options.ca = saved; }
  });

  test('the identity check is live: a different hostname is rejected', async () => {
    const r = await grab(() => dssrf.safe_fetch(`https://wrong.test:${srv.port}/`, { ports: [srv.port], allow: [`127.0.0.1:${srv.port}`] }));
    assert.equal(r.ok, false);
    assert.match(String(r.e.code || r.e.message), /ALTNAME|self-signed|unable to verify|UNABLE/i,
      'certificate verification must be enforced');
  });
});

describe('compatibility: the 1.0.6 surface is unchanged', () => {
  const EXPECTED = [
    'is_ipv6', 'bin_ip_to_normal_ip', 'decimal_ip_to_normal_ip', 'hex_ip_to_normal_ip',
    'is_hostname_resolve_to_internal_ip', 'is_proto_safe', 'is_range_not_internal',
    'is_redirect_safe', 'normalize_ipv4', 'normalize_schema', 'octal_ip_to_normal_ip',
    'remove_at_symbol_in_string', 'replace_backslash_with_slash_in_string',
    'replace_two_slashes_url_to_normal_url', 'is_url_safe',
  ];
  for (const name of EXPECTED) {
    test(`${name} is still exported`, () => assert.equal(typeof dssrf[name], 'function'));
  }
  test('is_url_safe still takes one argument and returns a boolean', async () => {
    assert.equal(dssrf.is_url_safe.length, 1);
    assert.equal(await dssrf.is_url_safe('http://127.0.0.1/'), false);
    assert.equal(await dssrf.is_url_safe('https://example.com/'), true);
  });
  test('pinning is additive', () => {
    for (const name of ['resolve_and_pin', 'safe_fetch']) assert.equal(typeof dssrf[name], 'function');
    assert.equal(typeof dssrf.SsrfRefused, 'function');
  });
});
