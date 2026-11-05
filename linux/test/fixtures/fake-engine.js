'use strict';

/* A fake engine for the Linux transport tests.
 *
 * It speaks the same private descriptor contract and the same loopback HTTP
 * routes as `hotspotshade gui`. It is not the real engine. The real engine is
 * tested in the disposable Linux VM with its demo backend.
 *
 * Arguments: gui --no-open --port 0 --port-file <path> --token-fd 3
 *            --parent-fd 4 [--demo] [--ignore-sigterm]
 *
 * The fake engine refuses to start when the secret appears in argv or in the
 * environment. That proves the transport keeps the secret on the descriptor.
 */

const fs = require('node:fs');
const http = require('node:http');

const args = process.argv.slice(2);
function option(name) {
  const index = args.indexOf(name);
  return index === -1 ? '' : args[index + 1] || '';
}

const portFile = option('--port-file');
const tokenFd = Number(option('--token-fd'));
const parentFd = Number(option('--parent-fd'));
const ignoreSigterm = args.includes('--ignore-sigterm');
const demo = args.includes('--demo');

if (!portFile || !Number.isInteger(tokenFd) || !Number.isInteger(parentFd)) {
  console.error('fake engine: missing descriptor arguments');
  process.exit(2);
}

function readSecret() {
  const chunks = [];
  const buffer = Buffer.alloc(256);
  for (;;) {
    let count = 0;
    try {
      count = fs.readSync(tokenFd, buffer, 0, buffer.length, null);
    } catch (error) {
      break;
    }
    if (count <= 0) break;
    chunks.push(Buffer.from(buffer.subarray(0, count)));
    if (buffer.subarray(0, count).includes(10)) break;
  }
  return Buffer.concat(chunks).toString('utf8').trim();
}

const secret = readSecret();
if (!/^[0-9a-f]{64}$/.test(secret)) {
  console.error('fake engine: the secret descriptor is empty or invalid');
  process.exit(3);
}
if (process.argv.join(' ').includes(secret)) {
  console.error('fake engine: the secret is on the command line');
  process.exit(4);
}
if (JSON.stringify(process.env).includes(secret)) {
  console.error('fake engine: the secret is in the environment');
  process.exit(5);
}

const state = {
  paired: false,
  running: false,
  lastStopReason: null,
  lastStopMessage: null,
  lastStopAt: null
};

function phone() {
  return {
    state: state.paired ? 'ready' : 'unpaired',
    message: state.paired ? 'The source device is ready.' : 'Pair with your source device to use it.',
    checked_at: Math.floor(Date.now() / 1000),
    connections: state.running ? 2 : null,
    trusted_by_source: state.paired,
    port_changed: false
  };
}

function status() {
  return {
    demo: true,
    api: 1,
    running: state.running,
    mode: state.running ? 'phone' : null,
    paired: state.paired,
    icmp_enabled: state.running,
    platform: { os: 'linux', arch: 'x64' },
    phone: phone(),
    forget: { state: 'none', attempts: 0 },
    last_stop: { reason: state.lastStopReason, at: state.lastStopAt },
    last_stop_message: state.lastStopMessage,
    engine: { version: 'fake', uptime_s: 1, workers: 1 }
  };
}

function json(response, statusCode, value) {
  const body = JSON.stringify(value);
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  response.end(body);
}

function authorized(request, port) {
  if (request.headers.authorization !== 'Bearer ' + secret) return false;
  if (request.headers.host !== '127.0.0.1:' + port) return false;
  return true;
}

function readBody(request) {
  return new Promise(function (resolve) {
    const chunks = [];
    request.on('data', function (chunk) { chunks.push(chunk); });
    request.on('end', function () {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch (error) {
        resolve(null);
      }
    });
  });
}

const server = http.createServer(function (request, response) {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (!authorized(request, server.address().port)) {
    json(response, 401, { ok: false, error: 'unauthorized' });
    return;
  }
  const route = request.method + ' ' + url.pathname;
  if (route === 'GET /api/status') {
    json(response, 200, status());
    return;
  }
  if (route === 'GET /api/phone/pair') {
    json(response, 200, { state: state.paired ? 'paired' : 'idle', code: null, error: null });
    return;
  }
  if (route === 'POST /api/phone/pair') {
    state.paired = true;
    json(response, 200, { state: 'paired', code: null, error: null });
    return;
  }
  if (route === 'POST /api/phone/pair/cancel') {
    json(response, 200, { state: 'idle', code: null, error: null });
    return;
  }
  if (route === 'POST /api/phone/forget') {
    if (state.running) {
      json(response, 409, { ok: false, error: 'Turn off the tunnel first.' });
      return;
    }
    state.paired = false;
    json(response, 200, { ok: true });
    return;
  }
  if (route === 'POST /api/phone/probe') {
    json(response, 200, { ok: true, phone: phone() });
    return;
  }
  if (route === 'POST /api/start') {
    readBody(request).then(function (body) {
      if (!body || body.mode !== 'phone') {
        json(response, 400, { ok: false, error: 'request body must be valid JSON' });
        return;
      }
      if (!state.paired) {
        json(response, 400, { ok: false, error: 'Pair with the source device first.' });
        return;
      }
      state.running = true;
      state.lastStopReason = null;
      state.lastStopMessage = null;
      state.lastStopAt = null;
      json(response, 200, { ok: true, status: status(), result: {} });
    });
    return;
  }
  if (route === 'POST /api/stop') {
    state.running = false;
    state.lastStopReason = 'user';
    state.lastStopMessage = 'You turned the tunnel off.';
    state.lastStopAt = Math.floor(Date.now() / 1000);
    json(response, 200, { ok: true, status: status(), result: {} });
    return;
  }
  if (route === 'GET /api/failures') {
    json(response, 200, {
      ok: true,
      since: 100,
      total: 1,
      dropped: 0,
      groups: [{ proto: 'tcp', family: 'ipv4', port: 443, reason: 'refused', phase: 'connect', count: 1, name: 'example.com', example_ip: '192.0.2.10', code: 5 }],
      recent: []
    });
    return;
  }
  if (route === 'GET /api/diagnostics') {
    json(response, 200, {
      ok: true,
      demo: true,
      running: state.running,
      engine: { version: 'fake', uptime_s: 1, workers: 1 },
      setup: {},
      dns: {},
      queues: { input: [], output: {} },
      udp: {},
      tcp: {},
      failures: { total: 0, dropped: 0 }
    });
    return;
  }
  if (route === 'GET /api/logs') {
    const since = Number(url.searchParams.get('since') || '0');
    json(response, 200, { logs: [{ seq: 1, ts: Math.floor(Date.now() / 1000), level: 'info', msg: 'Fake engine activity.' }].filter(function (entry) { return entry.seq > since; }), next: 1 });
    return;
  }
  json(response, 404, { ok: false, error: 'not found' });
});

let shuttingDown = false;
function shutdown(reason) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.error('fake-engine-exit: ' + reason + ' demo=' + String(demo));
  try {
    server.close();
  } catch (error) {
    /* Best effort. */
  }
  try {
    fs.unlinkSync(portFile);
  } catch (error) {
    /* Best effort. */
  }
  setTimeout(function () {
    process.exit(0);
  }, 20);
}

process.on('SIGTERM', function () {
  if (ignoreSigterm) {
    console.error('fake-engine-term: ignored');
    return;
  }
  shutdown('term');
});
process.on('SIGINT', function () {
  if (ignoreSigterm) return;
  shutdown('int');
});

try {
  const parent = fs.createReadStream(null, { fd: parentFd, autoClose: false });
  parent.on('end', function () { shutdown('parent'); });
  parent.on('error', function () { shutdown('parent'); });
  parent.resume();
} catch (error) {
  console.error('fake engine: the parent descriptor is not readable');
  process.exit(6);
}

server.listen(0, '127.0.0.1', function () {
  const port = server.address().port;
  fs.writeFileSync(portFile, String(port), { mode: 0o600 });
  console.log('fake engine ready on 127.0.0.1:' + port);
});
