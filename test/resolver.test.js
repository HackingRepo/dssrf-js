'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const dssrf = require('../dist/utils.js');
const { withStubResolver } = require('./harness.js');

describe('a resolver that cannot answer fails CLOSED', () => {
  test('NOERROR with zero answers is not "safe"', async () => {
    // The withholding-attacker signature: the zone answers, but with nothing.
    const stub = await withStubResolver({
      answer: () => null,
      hosts: { 'internal-jenkins.corp': null },   // getaddrinfo also fails
    });
    try {
      assert.equal(await dssrf.is_url_safe('http://internal-jenkins.corp/'), false,
        '"I could not check" must not be reported as "it is fine"');
    } finally { stub.restore(); }
  });

  test('resolve_host reports the distinction', async () => {
    const stub = await withStubResolver({ answer: () => null, hosts: { 'withheld.test': null } });
    try {
      const r = await dssrf.resolve_host('withheld.test');
      assert.equal(r.kind, 'unknown');
    } finally { stub.restore(); }
  });
});

describe('a name that genuinely does not exist is NOT an attack', () => {
  test('resolve_host classifies NXDOMAIN separately from unknown', async () => {
    const r = await dssrf.resolve_host('nonexistent-abc123xyz.invalid');
    assert.equal(r.kind, 'nxdomain');
  });

  test('a mistyped hostname is not reported as internal', async () => {
    assert.equal(await dssrf.is_hostname_resolve_to_internal_ip('examepjer-typo-xyz.invalid'), false);
  });
});

describe('the validator sees what the connecting resolver sees', () => {
  test('a host getaddrinfo maps internally is refused even when DNS says public', async () => {
    // dns.resolve* and dns.lookup disagree: /etc/hosts, split-horizon DNS,
    // container DNS and systemd-resolved all produce this, with no attacker
    // timing required. HTTP clients connect via getaddrinfo.
    const stub = await withStubResolver({
      answer: ({ qtype }) => (qtype === 1 ? '93.184.216.34' : null),
      hosts: { 'split.test': '10.0.0.5' },
    });
    try {
      assert.equal(await dssrf.is_url_safe('http://split.test/'), false);
    } finally { stub.restore(); }
  });
});

describe('resolution is cheap', () => {
  test('one validation costs at most 2 DNS queries', async () => {
    const stub = await withStubResolver({ answer: ({ qtype }) => (qtype === 1 ? '93.184.216.34' : null) });
    try {
      const before = stub.queries();
      await dssrf.is_url_safe('http://budget.test/');
      const spent = stub.queries() - before;
      assert.ok(spent <= 2, `${spent} queries for one call (1.0.7 spent 18)`);
    } finally { stub.restore(); }
  });

  test('no CNAME query is issued', async () => {
    // CNAME RDATA is always a domain name, never an IP literal
    const seen = [];
    const stub = await withStubResolver({
      answer: ({ qtype }) => { seen.push(qtype); return qtype === 1 ? '93.184.216.34' : null; },
    });
    try {
      await dssrf.is_url_safe('http://cname.test/');
      assert.ok(!seen.includes(5), `CNAME (qtype 5) was queried: ${seen}`);
    } finally { stub.restore(); }
  });

  test('a validation completes promptly', async () => {
    const stub = await withStubResolver({ answer: ({ qtype }) => (qtype === 1 ? '93.184.216.34' : null) });
    try {
      const t = Date.now();
      await dssrf.is_url_safe('http://timing.test/');
      const ms = Date.now() - t;
      assert.ok(ms < 500, `${ms}ms (1.0.7 slept 200-600ms by design)`);
    } finally { stub.restore(); }
  });
});

describe('a host resolving to any internal address is refused', () => {
  test('mixed public and internal answers', async () => {
    const stub = await withStubResolver({
      answer: ({ qtype }) => (qtype === 1 ? '93.184.216.34' : null),
      hosts: { 'mixed.test': '169.254.169.254' },
    });
    try {
      assert.equal(await dssrf.is_url_safe('http://mixed.test/'), false);
    } finally { stub.restore(); }
  });
});
