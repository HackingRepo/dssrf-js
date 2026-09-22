'use strict';
// Loopback-only test harness. node builtins only.

const dgram = require('node:dgram');
const http = require('node:http');
const dns = require('node:dns');

/** Minimal authoritative DNS responder. `answer` returns a dotted IPv4, or null for NODATA. */
function startDns(port, answer) {
  const sock = dgram.createSocket('udp4');
  let count = 0;
  sock.on('message', (msg, rinfo) => {
    const id = msg.readUInt16BE(0);
    let off = 12; const labels = [];
    while (msg[off] !== 0) { const l = msg[off]; labels.push(msg.slice(off + 1, off + 1 + l).toString()); off += 1 + l; }
    off += 1;
    const qtype = msg.readUInt16BE(off);
    const qsection = msg.slice(12, off + 4);
    count++;
    const rr = answer({ name: labels.join('.'), qtype, n: count });

    const head = Buffer.alloc(12);
    head.writeUInt16BE(id, 0); head.writeUInt16BE(0x8180, 2);
    head.writeUInt16BE(1, 4); head.writeUInt16BE(rr ? 1 : 0, 6);
    let body = Buffer.alloc(0);
    if (rr) {
      const b = Buffer.alloc(16);
      b.writeUInt16BE(0xC00C, 0); b.writeUInt16BE(1, 2); b.writeUInt16BE(1, 4);
      b.writeUInt32BE(0, 6); b.writeUInt16BE(4, 10);
      Buffer.from(rr.split('.').map(Number)).copy(b, 12);
      body = b;
    }
    sock.send(Buffer.concat([head, qsection, body]), rinfo.port, rinfo.address);
  });
  return new Promise((res) => sock.bind(port, '127.0.0.1', () => res({
    port: sock.address().port, close: () => sock.close(), count: () => count,
  })));
}

/** Always binds an ephemeral port: fixed ports collide when node --test runs
 *  several files at once, each in its own process. */
function startHttp(handler) {
  const srv = http.createServer(handler);
  return new Promise((res) => srv.listen(0, '127.0.0.1',
    () => res({ port: srv.address().port, close: () => srv.close() })));
}

const nextPort = () => 0;

/**
 * Point dns.resolve* at a local responder and optionally override getaddrinfo
 * for named hosts. Returns a restore function.
 */
async function withStubResolver({ answer, hosts = {} } = {}) {
  const server = answer ? await startDns(0, answer) : null;
  const savedServers = dns.getServers();
  const savedLookup = dns.promises.lookup;
  if (server) dns.setServers([`127.0.0.1:${server.port}`]);

  const entries = new Map(Object.entries(hosts));
  let lookups = 0;
  if (entries.size) {
    dns.promises.lookup = async (h, o) => {
      if (!entries.has(h)) return savedLookup(h, o);
      lookups++;
      const v = entries.get(h);
      const a = typeof v === 'function' ? v(lookups) : v;
      if (a === null) { const e = new Error('not found'); e.code = 'ENOTFOUND'; throw e; }
      return o && o.all ? [{ address: a, family: 4 }] : { address: a, family: 4 };
    };
  }

  return {
    queries: () => (server ? server.count() : 0),
    lookups: () => lookups,
    restore() {
      server?.close();
      dns.setServers(savedServers);
      dns.promises.lookup = savedLookup;
    },
  };
}

module.exports = { startDns, startHttp, nextPort, withStubResolver };
