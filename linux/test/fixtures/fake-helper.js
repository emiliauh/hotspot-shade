'use strict';

/* A fake privileged helper for the hermetic transport test.
 *
 * The test starts this script in place of pkexec. It receives the fixed helper
 * path as its only program argument. It reads the version line and the secret
 * from stdin, starts a small loopback HTTP service, and prints `HS_PORT <n>`.
 * It stops when stdin closes.
 *
 * It is not the real helper. It proves the client contract: pkexec with one
 * fixed helper path, no secret in argv or the environment, and a stop that
 * closes the request pipe.
 */

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const args = process.argv.slice(2);
const helperPath = args[0] || '';
const deny = path.basename(helperPath).includes('deny');

let requestBuffer = Buffer.alloc(0);
const readers = [];

function flushReaders() {
  for (;;) {
    if (!readers.length) return;
    const index = requestBuffer.indexOf(10);
    if (index === -1) return;
    const line = requestBuffer.subarray(0, index).toString('utf8');
    requestBuffer = requestBuffer.subarray(index + 1);
    const reader = readers.shift();
    if (line.length > reader.limit) reader.resolve('');
    else reader.resolve(line);
  }
}

function readLine(file, limit) {
  return new Promise((resolve) => {
    readers.push({ limit, resolve });
    flushReaders();
  });
}

process.stdin.on('data', function (chunk) {
  requestBuffer = Buffer.concat([requestBuffer, chunk]);
  flushReaders();
});
process.stdin.on('end', function () {
  while (readers.length) readers.shift().resolve('');
});
process.stdin.on('error', function () {
  while (readers.length) readers.shift().resolve('');
});
process.stdin.resume();

const state = {
  paired: true,
  running: false
};

function status() {
  return {
    demo: true,
    api: 1,
    running: state.running,
    mode: state.running ? 'phone' : null,
    paired: state.paired,
    icmp_enabled: state.running,
    platform: { os: 'linux', arch: 'x64' },
    phone: {
      state: state.paired ? 'ready' : 'unpaired',
      message: state.paired ? 'The source device is ready.' : 'Pair with your source device.',
      checked_at: Math.floor(Date.now() / 1000),
      connections: state.running ? 1 : null,
      trusted_by_source: state.paired,
      port_changed: false
    },
    forget: { state: 'none', attempts: 0 },
    last_stop: { reason: null, at: null },
    last_stop_message: null,
    engine: { version: 'fake-helper', uptime_s: 1, workers: 1 }
  };
}

function json(response, statusCode, value) {
  const body = JSON.stringify(value);
  response.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body)
  });
  response.end(body);
}

async function main() {
  const version = await readLine(process.stdin, 16);
  if (version !== 'HS1') {
    console.error('fake helper: bad version');
    process.exit(2);
  }
  const secret = await readLine(process.stdin, 128);
  if (!/^[0-9a-f]{64}$/.test(secret)) {
    console.error('fake helper: bad secret');
    process.exit(3);
  }
  if (process.argv.join(' ').includes(secret)) {
    console.error('fake helper: secret in argv');
    process.exit(4);
  }
  if (JSON.stringify(process.env).includes(secret)) {
    console.error('fake helper: secret in environment');
    process.exit(5);
  }
  if (deny) {
    console.error('fake helper: authorization denied');
    process.exit(127);
  }

  const server = http.createServer(function (request, response) {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (request.headers.authorization !== 'Bearer ' + secret) {
      json(response, 401, { ok: false, error: 'unauthorized' });
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/status') {
      json(response, 200, status());
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/phone/pair') {
      json(response, 200, { state: state.paired ? 'paired' : 'idle', code: null, error: null });
      return;
    }
    json(response, 404, { ok: false, error: 'not found' });
  });

  server.listen(0, '127.0.0.1', function () {
    process.stdout.write('fake helper ready\n');
    process.stdout.write('HS_PORT ' + server.address().port + '\n');
  });

  process.stdin.on('end', function () {
    server.close(function () {
      process.exit(0);
    });
  });
  process.stdin.on('error', function () {
    process.exit(0);
  });
  process.stdin.resume();
}

main().catch(function () {
  console.error('fake helper: failed');
  process.exit(6);
});
