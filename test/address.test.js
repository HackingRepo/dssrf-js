'use strict';
// Address classification. Runs against dist/ -- what npm consumers execute.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const dssrf = require('../dist/utils.js');

const INTERNAL_V4 = [
  '127.0.0.1', '127.0.0.2', '10.0.0.1', '172.16.0.1', '192.168.1.1',
  '169.254.169.254', '100.64.0.1', '0.0.0.0', '255.255.255.255',
  '192.0.0.1', '198.18.0.1', '203.0.113.1', '224.0.0.1', '240.0.0.1',
  '168.63.129.16', '100.100.100.200',
];

// An IPv4 address means the same thing however it is wrapped in IPv6.
const EMBEDDINGS = {
  'ipv4-mapped':     (v4) => `::ffff:${v4}`,
  'ipv4-compatible': (v4) => `::${v4}`,
  'nat64':           (v4) => `64:ff9b::${v4}`,
  '6to4':            (v4) => {
    const o = v4.split('.').map(Number);
    return `2002:${(((o[0] << 8) | o[1]) >>> 0).toString(16)}:${(((o[2] << 8) | o[3]) >>> 0).toString(16)}::`;
  },
};

describe('internal IPv4 literals are refused', () => {
  for (const ip of INTERNAL_V4) {
    test(ip, () => assert.equal(dssrf.is_ip_internal(ip), true));
  }
});

describe('IPv4-in-IPv6 embeddings classify as the embedded address', () => {
  for (const v4 of ['127.0.0.1', '169.254.169.254', '10.0.0.1']) {
    for (const [name, embed] of Object.entries(EMBEDDINGS)) {
      const v6 = embed(v4);
      test(`${name}: ${v6} = ${v4}`, () => {
        assert.equal(dssrf.is_ip_internal(v6), true);
      });
    }
  }
});

describe('native IPv6 internal ranges are refused', () => {
  for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd00::1', 'ff02::1',
                    'fec0::1', '5f00::1', '3fff::1', '64:ff9b:1::1', '100::1']) {
    test(ip, () => assert.equal(dssrf.is_ip_internal(ip), true));
  }
});

describe('public addresses are allowed', () => {
  for (const ip of ['93.184.216.34', '8.8.8.8', '1.1.1.1', '2606:4700::1111', '2001:4860:4860::8888']) {
    test(ip, () => assert.equal(dssrf.is_ip_internal(ip), false));
  }
});

describe('is_ip_internal is total: it never throws and never defaults to allow', () => {
  for (const v of ['127.1', '0x7f000001', '2130706433', '0177.0.0.1', '1.2.3.4.5',
                   '', 'not-an-ip', '127.0.0.1.', '999.999.999.999']) {
    test(JSON.stringify(v), () => {
      let r;
      assert.doesNotThrow(() => { r = dssrf.is_ip_internal(v); });
      assert.equal(typeof r, 'boolean');
      // Anything ipaddr cannot canonicalise must be refused, not allowed.
      if (!require('ipaddr.js').isValid(v)) assert.equal(r, true, 'unparseable input must be refused');
    });
  }
});

describe('is_range_not_internal handles both families', () => {
  const cases = [
    ['8.8.8.0/24', true], ['1.1.1.1/32', true],
    ['127.0.0.0/8', false], ['10.0.0.0/8', false], ['0.0.0.0/0', false],
    ['::1/128', false], ['fc00::/7', false], ['fe80::/10', false],
    ['2606:4700::/32', true], ['2001:4860:4860::/48', true],
  ];
  for (const [cidr, expected] of cases) {
    test(`${cidr} -> ${expected ? 'external' : 'internal'}`, () => {
      assert.equal(dssrf.is_range_not_internal(cidr), expected);
    });
  }
});
