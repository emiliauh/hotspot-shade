'use strict';

/* A fake privileged helper for the hermetic transport test.
 *
 * The test starts this script in place of pkexec. It receives the fixed helper
 * path as its only program argument. It reads the version line and the secret
 * from stdin, prints `HS_READY`, starts a small loopback HTTP service, and
 * prints `HS_PORT <n>`. It stops when stdin closes.
 *
 * It is not the real helper. It proves the client contract: pkexec with one
 * fixed helper path, no secret in argv or the environment, a stop that closes
 * the request pipe, and the helper status protocol. Environment settings let a
 * test delay authorization, report a helper timeout, or exit in a specific
 * way. None of them starts a real engine or changes a host route.
 */

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const args = process.argv.slice(2);
const helperPath = args[0] || '';
const deny = path.basename(helperPath).includes('deny');

function numberSetting(name) {
  return Math.max(0, Number(process.env[name]) || 0);
}

const authorizationDelayMs = numberSetting('HS_FAKE_HELPER_AUTHORIZATION_DELAY_MS');
const exitDelayMs = numberSetting('HS_FAKE_HELPER_EXIT_DELAY_MS');
const stopTimeoutDelayMs = numberSetting('HS_FAKE_HELPER_STOP_TIMEOUT_DELAY_MS');
const exitCode = Number.isInteger(Number(process.env.HS_FAKE_HELPER_EXIT_CODE))
  ? Number(process.env.HS_FAKE_HELPER_EXIT_CODE)
  : 0;
const exitBeforeReady = Number.isInteger(Number(process.env.HS_FAKE_HELPER_EXIT_BEFORE_READY))
  ? Number(process.env.HS_FAKE_HELPER_EXIT_BEFORE_READY)
  : 0;
const exitSignal = typeof process.env.HS_FAKE_HELPER_SIGNAL === 'string'
  ? process.env.HS_FAKE_HELPER_SIGNAL.trim()
  : '';
const startedMarker = typeof process.env.HS_FAKE_HELPER_STARTED_MARKER === 'string'
  ? process.env.HS_FAKE_HELPER_STARTED_MARKER
  : '';

/* The real helper runs as root, so the app cannot signal it. A client that
 * sends SIGTERM must be visible in the test, not silently ignored. */
process.on('SIGTERM', function () {
  process.exit(42);
});

let requestBuffer = Buffer.alloc(0);
let requestClosed = false;
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

function requestEnded() {
  requestClosed = true;
  while (readers.length) readers.shift().resolve('');
}

process.stdin.on('data', function (chunk) {
  requestBuffer = Buffer.concat([requestBuffer, chunk]);
  flushReaders();
});
process.stdin.on('end', requestEnded);
process.stdin.on('error', requestEnded);
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

function delay(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function stopSelf(code) {
  if (exitSignal) {
    process.kill(process.pid, exitSignal);
    setTimeout(function () { process.exit(code || 1); }, 1000).unref();
    return;
  }
  process.exit(code);
}

let reasonStream = process.stderr;

async function main() {
  const version = await readLine(process.stdin, 16);
  /* HS2 passes the user engine handoff socket as descriptor 2. Like the real
   * helper, this fake then writes its reason lines on stdout. It never reads
   * descriptor 2. */
  const handoff = version === 'HS2';
  if (handoff) reasonStream = process.stdout;
  if (process.env.HS_FAKE_HELPER_VERSION_FILE) {
    let socket = false;
    try { socket = fs.fstatSync(2).isSocket(); } catch (error) { socket = false; }
    fs.writeFileSync(process.env.HS_FAKE_HELPER_VERSION_FILE, version + (handoff ? (socket ? ' socket' : ' not-socket') : ''));
  }
  if (version !== 'HS1' && !handoff) {
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
  if (exitBeforeReady) {
    /* A test can ask for stderr noise before the reason line, and for an
     * unlisted or hostile reason line. Exit from the write callback: a large
     * pipe write can be asynchronous, and process.exit would cut it off. */
    const flood = numberSetting('HS_FAKE_HELPER_STDERR_FLOOD');
    let text = flood > 0 ? 'x'.repeat(flood) + '\n' : '';
    if (typeof process.env.HS_FAKE_HELPER_REASON === 'string') {
      text += process.env.HS_FAKE_HELPER_REASON + '\n';
    }
    text += 'fake helper: refusing before readiness\n';
    reasonStream.write(text, () => process.exit(exitBeforeReady));
    return;
  }

  /* pkexec can spend a long time on the password prompt. Hold the readiness
   * line until the test allows it. If the app closed the request pipe while
   * the prompt was open, do not start an engine that nobody waits for. */
  if (authorizationDelayMs > 0) {
    await delay(authorizationDelayMs);
  }
  if (requestClosed) {
    console.error('fake helper: the request pipe closed before readiness');
    process.exit(7);
  }
  process.stdout.write('HS_READY\n');

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

  let finished = false;
  let listening = false;
  let finishRequested = false;
  function finish() {
    if (!listening) {
      finishRequested = true;
      return;
    }
    if (finished) return;
    finished = true;
    server.close(function () {
      if (stopTimeoutDelayMs > 0) {
        process.stdout.write('HS_STOP_TIMEOUT\n');
        setTimeout(function () {
          stopSelf(exitCode);
        }, stopTimeoutDelayMs);
        return;
      }
      if (exitDelayMs > 0) {
        setTimeout(function () {
          stopSelf(exitCode);
        }, exitDelayMs);
        return;
      }
      stopSelf(exitCode);
    });
  }

  process.stdin.on('end', finish);
  process.stdin.on('error', finish);
  server.listen(0, '127.0.0.1', function () {
    listening = true;
    if (startedMarker) {
      try {
        fs.writeFileSync(startedMarker, 'started\n', { mode: 0o600 });
      } catch (error) {
        /* The marker is a test aid only. */
      }
    }
    const port = String(server.address().port);
    if (process.env.HS_FAKE_HELPER_SPLIT_PORT === '1') {
      process.stdout.write('HS_PORT ' + port.slice(0, -1));
      setTimeout(function () { process.stdout.write(port.slice(-1) + '\n'); }, 150);
    } else {
      process.stdout.write('HS_PORT ' + port + '\n');
    }
    if (requestClosed || finishRequested) finish();
  });
}

main().catch(function () {
  console.error('fake helper: failed');
  process.exit(6);
});
