'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const dssrf = require('../dist/utils.js');

const safe = (u) => dssrf.is_url_safe(u);

describe('internal destinations are refused through the URL API', () => {
  for (const u of [
    'http://127.0.0.1/', 'https://127.0.0.1/', 'http://localhost/', 'http://127.1/',
    'http://2130706433/', 'http://0x7f000001/', 'http://0177.0.0.1/', 'http://0/',
    'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.1/', 'http://192.168.0.1/',
    'http://172.16.0.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[fe80::1]/',
    'http://[fc00::1]/', 'http://[::]/', 'http://0.0.0.0/',
    // the 1.0.7 bypasses
    'http://[::7f00:1]/', 'http://[::a9fe:a9fe]/', 'http://[::127.0.0.1]/', 'http://[::169.254.169.254]/',
    // encodings and authority confusion
    'http://%31%32%37%2E%30%2E%30%2E%31/', 'http://user@127.0.0.1/', 'http://a@169.254.169.254/',
    'http:\\\\127.0.0.1/', '//127.0.0.1/', 'http:/127.0.0.1/', 'http:///127.0.0.1/',
    'http://127.0.0.1#@example.com/', 'HTTP://127.0.0.1/',
  ]) {
    test(JSON.stringify(u), async () => assert.equal(await safe(u), false));
  }
});

describe('non-http schemes are refused', () => {
  for (const u of ['file:///etc/passwd', 'gopher://127.0.0.1:11211/', 'dict://127.0.0.1:11211/',
                   'ftp://127.0.0.1/', 'jar:http://127.0.0.1!/', 'data:text/plain,x', 'javascript:alert(1)']) {
    test(u, async () => assert.equal(await safe(u), false));
  }
});

describe('malformed input fails closed without throwing', () => {
  for (const v of [null, undefined, 123, {}, ['http://x'], '', 'not a url', 'http://']) {
    test(JSON.stringify(v), async () => assert.equal(await safe(v), false));
  }
});

/// Legitimate url paths must not be rejected, our previous fix of the GHSA, is too strict, now we fixed it
describe('legitimate international URLs are NOT refused', () => {
  for (const u of ['https://example.com/M%C3%BCller.pdf', 'https://example.com/Müller.pdf',
                   'https://example.com/検索', 'https://example.com/?q=café',
                   'https://xn--80akhbyknj4f.xn--p1ai/']) {
    test(u, async () => assert.equal(await safe(u), true));
  }
});

describe('homoglyph and percent-encoded hosts still resolve to their canonical form', () => {
  for (const u of ['http://%E2%93%81ocalhost/', 'http://%6C%6F%63%61%6C%68%6F%73%74/',
                   'http://loc%61lhost/', 'http://ⓁⓄⒸⒶⓁⒽⓄⓈⓉ/', 'http://LOCALHOST./']) {
    test(u, async () => assert.equal(await safe(u), false));
  }
});

describe('exported helpers keep their 1.0.7 behaviour', () => {
  test('is_proto_safe', () => {
    assert.equal(dssrf.is_proto_safe('https://x'), true);
    assert.equal(dssrf.is_proto_safe('http:'), true);
    assert.equal(dssrf.is_proto_safe('file:'), false);
    assert.equal(dssrf.is_proto_safe(''), false);
  });
  test('encoding converters', () => {
    assert.equal(dssrf.octal_ip_to_normal_ip('0177.0.0.1'), '127.0.0.1');
    assert.equal(dssrf.hex_ip_to_normal_ip('0x7f000001'), '127.0.0.1');
    assert.equal(dssrf.decimal_ip_to_normal_ip('2130706433'), '127.0.0.1');
    assert.equal(dssrf.bin_ip_to_normal_ip('01111111000000000000000000000001'), '127.0.0.1');
    assert.equal(dssrf.normalize_ipv4('192.168.1.1'), '192.168.1.1');
    assert.throws(() => dssrf.normalize_ipv4('192.168.001.1'));
  });
  test('string rewriters', () => {
    assert.equal(dssrf.replace_backslash_with_slash_in_string('a\\b'), 'a/b');
    assert.equal(dssrf.remove_at_symbol_in_string('a@b'), 'ab');
    assert.equal(dssrf.normalize_schema('https://x/'), 'https:');
    assert.equal(dssrf.replace_two_slashes_url_to_normal_url('//x'), 'http://x');
  });
  test('is_ipv6', () => {
    assert.equal(dssrf.is_ipv6('::1'), true);
    assert.equal(dssrf.is_ipv6('127.0.0.1'), false);
  });
});
