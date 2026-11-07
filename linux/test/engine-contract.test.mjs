import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createEngineHttpClient } = require('../src/backend/engine-client.js');

/* A fixed public test secret. It is written to descriptor 3 only. The engine
 * reads one 64-character lowercase hex line, so this value is valid and never
 * appears on a command line or in the environment. */
const SECRET = 'ab'.repeat(32);
const WRONG_SECRET = 'cd'.repeat(32);
const LOOPBACK = '127.0.0.1';

const START_TIMEOUT_MS = 10000;
const REQUEST_TIMEOUT_MS = 3000;
const PAIR_TIMEOUT_MS = 8000;
const EXIT_TIMEOUT_MS = 5000;
const CLEANUP_TIMEOUT_MS = 3000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

const ENGINE_BIN = typeof process.env.HOTSPOTSHADE_BIN === 'string'
  ? process.env.HOTSPOTSHADE_BIN.trim()
  : '';

function engineSkipReason() {
  if (process.platform === 'win32') {
    return 'The real-engine contract test uses Unix descriptors 3 and 4. Run it on macOS or Linux.';
  }
  if (!ENGINE_BIN) {
    return 'HOTSPOTSHADE_BIN is not set. Point it at a built hotspotshade binary to run the real-engine contract test.';
  }
  return false;
}

function validateEngineBin() {
  if (!path.isAbsolute(ENGINE_BIN)) {
    throw new Error('HOTSPOTSHADE_BIN must be an absolute file path. The test does not search PATH.');
  }
  let stat;
  try {
    stat = fs.statSync(ENGINE_BIN);
  } catch (error) {
    throw new Error('HOTSPOTSHADE_BIN does not name an existing file: ' + ENGINE_BIN);
  }
  if (!stat.isFile()) {
    throw new Error('HOTSPOTSHADE_BIN does not name a regular file: ' + ENGINE_BIN);
  }
  try {
    fs.accessSync(ENGINE_BIN, fs.constants.X_OK);
  } catch (error) {
    throw new Error('HOTSPOTSHADE_BIN is not executable: ' + ENGINE_BIN);
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    if (typeof timer.unref === 'function') timer.unref();
  });
}

function within(promise, milliseconds, message) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), milliseconds);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function parseJson(response) {
  return JSON.parse(response.body);
}

function requestRaw(port, options) {
  const settings = options && typeof options === 'object' ? options : {};
  const body = typeof settings.body === 'string' ? settings.body : '';
  const headers = Object.assign({
    Host: LOOPBACK + ':' + port,
    Connection: 'close'
  }, settings.headers || {});
  if (body) headers['Content-Length'] = String(Buffer.byteLength(body));
  return new Promise((resolve, reject) => {
    let settled = false;
    function finish(error, value) {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    }
    const request = http.request({
      host: LOOPBACK,
      port: port,
      method: typeof settings.method === 'string' ? settings.method : 'GET',
      path: typeof settings.path === 'string' ? settings.path : '/api/status',
      agent: false,
      headers: headers
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          response.destroy();
          finish(new Error('The engine response is too large.'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        finish(null, {
          statusCode: Number(response.statusCode) || 0,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8')
        });
      });
      response.on('error', (error) => finish(error));
    });
    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy();
      finish(new Error('The engine request timed out.'));
    });
    request.on('error', (error) => finish(error));
    if (body) request.write(body);
    request.end();
  });
}

function assertJsonResponse(response, expectedStatus) {
  assert.equal(response.statusCode, expectedStatus);
  assert.match(response.headers['content-type'] || '', /^application\/json/);
  assert.match(response.headers['cache-control'] || '', /no-store/);
  return parseJson(response);
}

function assertStatusShape(status) {
  assert.ok(status && typeof status === 'object' && !Array.isArray(status));
  assert.equal(status.demo, true);
  assert.equal(status.api, 1);
  assert.equal(typeof status.running, 'boolean');
  assert.equal(typeof status.iface, 'string');
  assert.ok(status.error === null || typeof status.error === 'string');
  assert.ok(status.stats && typeof status.stats === 'object');
  assert.equal(status.stats.ttl_bad, 0);
  assert.ok(status.platform && typeof status.platform === 'object');
  assert.equal(typeof status.platform.os, 'string');
  assert.ok(status.phone && typeof status.phone === 'object');
  assert.equal(typeof status.phone.state, 'string');
  assert.ok(status.forget && typeof status.forget === 'object');
  assert.equal(typeof status.forget.state, 'string');
  assert.equal(typeof status.forget.attempts, 'number');
  assert.ok(Object.hasOwn(status, 'last_stop'));
  assert.ok(Object.hasOwn(status, 'last_stop_message'));
}

function assertDiagnosticsShape(value) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.equal(value.ok, true);
  assert.equal(value.demo, true);
  assert.equal(typeof value.running, 'boolean');
  assert.ok(value.engine && typeof value.engine === 'object');
  assert.equal(typeof value.engine.version, 'string');
  assert.equal(typeof value.engine.uptime_s, 'number');
  assert.equal(typeof value.engine.workers, 'number');
  for (const name of ['connect_ms', 'greeting_ms', 'auth_ms', 'request_ms']) {
    assert.ok(value.setup && value.setup[name] && typeof value.setup[name] === 'object');
    assert.ok(Number.isInteger(value.setup[name].count));
    assert.ok(Number.isInteger(value.setup[name].p50));
    assert.ok(Number.isInteger(value.setup[name].p95));
    assert.ok(Number.isInteger(value.setup[name].max));
  }
  assert.equal(typeof value.dns.lookups, 'number');
  assert.equal(typeof value.dns.ok, 'number');
  assert.equal(typeof value.dns.failed, 'number');
  assert.ok(Array.isArray(value.queues.input));
  assert.ok(value.queues.output && typeof value.queues.output === 'object');
  assert.equal(typeof value.udp.flows, 'number');
  assert.equal(typeof value.udp.age_drops, 'number');
  assert.equal(typeof value.tcp.flows_peak, 'number');
  assert.equal(typeof value.tcp.retransmits, 'number');
  assert.equal(typeof value.tcp.zero_window_ms, 'number');
  assert.ok(value.destination_privacy && typeof value.destination_privacy === 'object');
  assert.equal(typeof value.destination_privacy.mode, 'string');
  assert.ok(value.failures && typeof value.failures === 'object');
  assert.ok(Number.isInteger(value.failures.total));
  assert.ok(Number.isInteger(value.failures.dropped));
}

async function launchEngine() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-contract-'));
  let child = null;
  let exit = null;
  let exited = null;
  let output = '';
  try {
    fs.chmodSync(directory, 0o700);
    assert.equal(fs.statSync(directory).mode & 0o777, 0o700, 'the private temporary directory is mode 0700');
    const portFile = path.join(directory, 'port');
    const portFileTemp = portFile + '.tmp';
    const args = [
      'gui',
      '--demo',
      '--no-open',
      '--port',
      '0',
      '--port-file',
      portFile,
      '--token-fd',
      '3',
      '--parent-fd',
      '4'
    ];
    child = spawn(ENGINE_BIN, args, {
      cwd: directory,
      env: {
        HOME: directory,
        TMPDIR: directory,
        PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
        LANG: 'C.UTF-8'
      },
      stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'],
      detached: false,
      windowsHide: true
    });

    exited = new Promise((resolve) => {
      child.once('exit', (code, signal) => {
        exit = { code: code, signal: signal || null };
        resolve(exit);
      });
      child.once('error', () => {
        if (exit) return;
        exit = { code: null, signal: null, error: true };
        resolve(exit);
      });
    });
    function collect(stream) {
      if (!stream) return;
      stream.setEncoding('utf8');
      stream.on('data', (chunk) => {
        output = (output + String(chunk)).slice(-8000);
      });
    }
    collect(child.stdout);
    collect(child.stderr);

    assert.ok(child.spawnargs && child.spawnargs.includes('--token-fd'), 'the token descriptor is passed');
    assert.equal(child.spawnargs.join(' ').includes(SECRET), false, 'the secret never appears in the command line');
    assert.equal(child.spawnargs.includes('--demo'), true, 'the test launches the in-memory demo backend');
    assert.ok(child.spawnargs.includes('--parent-fd'), 'the parent descriptor is passed');
    assert.equal(
      child.spawnargs[child.spawnargs.indexOf('--token-fd') + 1],
      '3',
      'the token descriptor is fd 3'
    );
    assert.equal(
      child.spawnargs[child.spawnargs.indexOf('--parent-fd') + 1],
      '4',
      'the parent descriptor is fd 4'
    );
    if (fs.existsSync('/proc/' + child.pid + '/cmdline')) {
      const commandLine = fs.readFileSync('/proc/' + child.pid + '/cmdline', 'utf8');
      assert.equal(commandLine.includes(SECRET), false, 'the running process command line holds no secret');
    }

    const tokenStream = child.stdio ? child.stdio[3] : null;
    assert.ok(tokenStream && typeof tokenStream.end === 'function', 'the token pipe exists');
    tokenStream.on('error', () => {
      /* A closed token pipe is reported by the startup wait. */
    });
    await new Promise((resolve, reject) => {
      tokenStream.end(SECRET + '\n', () => {
        if (typeof tokenStream.destroy === 'function' && !tokenStream.destroyed) {
          tokenStream.destroy();
        }
        resolve();
      });
      tokenStream.once('error', reject);
    });

    const deadline = Date.now() + START_TIMEOUT_MS;
    let port = null;
    while (Date.now() < deadline) {
      if (exit) {
        throw new Error('The engine exited during startup: ' + JSON.stringify(exit) + '\n' + output);
      }
      try {
        const text = fs.readFileSync(portFile, 'utf8').trim();
        if (/^[0-9]{1,5}$/.test(text)) {
          const value = Number(text);
          if (value > 0 && value <= 65535) {
            port = value;
            break;
          }
        }
      } catch (error) {
        /* The port file is written after the listener binds. */
      }
      await delay(25);
    }
    if (!port) {
      throw new Error('The engine did not write a loopback port in time.\n' + output);
    }
    assert.equal(fs.statSync(portFile).mode & 0o777, 0o600, 'the port file is mode 0600');

    return {
      child: child,
      directory: directory,
      portFile: portFile,
      portFileTemp: portFileTemp,
      port: port,
      output: () => output,
      exitInfo: () => (exit ? Object.assign({}, exit) : null),
      exited: exited
    };
  } catch (error) {
    if (child) {
      try {
        child.kill('SIGTERM');
      } catch (killError) {
        /* The engine is already gone. */
      }
      if (exited) {
        try {
          await within(exited, CLEANUP_TIMEOUT_MS, 'The engine did not stop after a failed startup.');
        } catch (stopError) {
          try {
            child.kill('SIGKILL');
          } catch (killError) {
            /* The engine is already gone. */
          }
          try {
            await within(exited, CLEANUP_TIMEOUT_MS, 'The engine did not stop after a failed startup.');
          } catch (finalError) {
            /* Best-effort cleanup. The original failure is reported below. */
          }
        }
      }
    }
    try {
      fs.rmSync(directory, { recursive: true, force: true });
    } catch (cleanupError) {
      /* The temporary directory is best-effort cleanup. */
    }
    throw error;
  }
}

async function closeEngine(engine) {
  if (!engine || !engine.child) return;
  if (!engine.exitInfo()) {
    try {
      engine.child.kill('SIGTERM');
    } catch (error) {
      /* The engine is already gone. */
    }
    try {
      await within(engine.exited, EXIT_TIMEOUT_MS, 'The engine did not stop after SIGTERM.');
    } catch (error) {
      try {
        engine.child.kill('SIGKILL');
      } catch (killError) {
        /* The engine is already gone. */
      }
      await within(engine.exited, CLEANUP_TIMEOUT_MS, 'The engine did not stop after SIGKILL.');
    }
  }
  try {
    fs.rmSync(engine.directory, { recursive: true, force: true });
  } catch (error) {
    /* The temporary directory is best-effort cleanup. */
  }
}

test('the real engine HTTP contract matches the Linux client', {
  skip: engineSkipReason(),
  timeout: 60000
}, async (t) => {
  validateEngineBin();
  const engine = await launchEngine();
  const client = createEngineHttpClient({ port: engine.port, secret: SECRET });

  try {
    await t.test('the bearer challenge rejects a missing or wrong secret', async () => {
      const missing = await requestRaw(engine.port, { path: '/api/status' });
      assert.deepEqual(assertJsonResponse(missing, 401), {
        ok: false,
        error: 'unauthorized'
      });
      assert.equal(missing.headers['www-authenticate'], undefined);

      const wrong = await requestRaw(engine.port, {
        path: '/api/status',
        headers: { Authorization: 'Bearer ' + WRONG_SECRET }
      });
      assert.deepEqual(assertJsonResponse(wrong, 401), {
        ok: false,
        error: 'unauthorized'
      });

      const wrongClient = createEngineHttpClient({ port: engine.port, secret: WRONG_SECRET });
      await assert.rejects(wrongClient.call('status'), (error) => {
        assert.equal(error.code, 'engine_unauthorized');
        assert.equal(error.message, 'The engine rejected the request.');
        assert.equal(error.status, 401);
        return true;
      });
    });

    await t.test('the authenticated loopback contract rejects a foreign Host and Origin', async () => {
      const auth = { Authorization: 'Bearer ' + SECRET };
      const foreignHost = await requestRaw(engine.port, {
        path: '/api/status',
        headers: Object.assign({}, auth, { Host: 'localhost:' + engine.port })
      });
      assert.deepEqual(assertJsonResponse(foreignHost, 403), {
        ok: false,
        error: 'forbidden: invalid Host'
      });

      const foreignOrigin = await requestRaw(engine.port, {
        path: '/api/status',
        headers: Object.assign({}, auth, { Origin: 'http://attacker.invalid' })
      });
      assert.deepEqual(assertJsonResponse(foreignOrigin, 403), {
        ok: false,
        error: 'forbidden: invalid Origin'
      });

      const status = await requestRaw(engine.port, {
        path: '/api/status',
        headers: Object.assign({}, auth, { Origin: 'http://' + LOOPBACK + ':' + engine.port })
      });
      assert.equal(status.statusCode, 200);
    });

    await t.test('the status answer has the real stopped envelope', async () => {
      const status = await client.call('status');
      assertStatusShape(status);
      assert.equal(status.running, false);
      assert.equal(status.mode, null);
      assert.equal(status.error, null);
      assert.equal(status.icmp_enabled, false);
      assert.deepEqual(status.last_stop, { reason: null, at: null });
      assert.equal(status.last_stop_message, null);
      assert.equal(status.paired, false);
      assert.equal(status.phone_host, null);
      assert.equal(status.phone_port, null);
    });

    await t.test('the unpaired probe reports the source device CHALLENGE state', async () => {
      const first = await client.call('probe');
      assert.equal(first.ok, true);
      assert.equal(first.demo, true);
      assert.ok(first.phone && typeof first.phone === 'object');
      assert.equal(typeof first.phone.state, 'string');
      assert.equal(typeof first.phone.trusted_by_source, 'boolean');

      const second = await client.call('probe');
      assert.equal(typeof second.phone.trusted_by_source, 'boolean');
      assert.notEqual(
        first.phone.trusted_by_source,
        second.phone.trusted_by_source,
        'the demo alternates the CHALLENGE known byte'
      );

      const status = await client.call('status');
      assert.equal(typeof status.phone.checked_at, 'number');
      assert.equal(typeof status.phone.trusted_by_source, 'boolean');
    });

    await t.test('a start before pairing returns the fixed error envelope', async () => {
      await assert.rejects(client.call('start', { mode: 'phone', ping: true }), (error) => {
        assert.equal(error.code, 'engine_error');
        assert.equal(error.message, 'Pair with the source device first.');
        assert.equal(error.status, 400);
        return true;
      });

      const status = await client.call('status');
      assert.equal(status.running, false);
    });

    await t.test('pairing reaches the paired state without exposing a token', async () => {
      const initial = await client.call('pairState');
      assert.equal(initial.state, 'idle');
      assert.equal(initial.code, null);
      assert.equal(initial.error, null);
      assert.equal(Object.hasOwn(initial, 'token'), false);

      const started = await client.call('pair');
      assert.ok(started.state === 'connecting' || started.state === 'confirm');
      assert.equal(started.demo, true);
      assert.equal(started.error, null);
      assert.equal(Object.hasOwn(started, 'token'), false);

      let paired = null;
      const deadline = Date.now() + PAIR_TIMEOUT_MS;
      while (Date.now() < deadline) {
        const state = await client.call('pairState');
        if (state.state === 'paired') {
          paired = state;
          break;
        }
        await delay(100);
      }
      assert.ok(paired, 'pairing reached the paired state in time');
      assert.equal(paired.host, '172.20.10.1');
      assert.equal(paired.port, 31000);
      assert.equal(paired.error, null);
      assert.equal(Object.hasOwn(paired, 'token'), false);
    });

    await t.test('start, duplicate start, and forget while running return real envelopes', async () => {
      const started = await client.call('start', { mode: 'phone', ping: true });
      assertStatusShape(started);
      assert.equal(started.running, true);
      assert.equal(started.mode, 'phone');
      assert.equal(started.icmp_enabled, true);
      assert.equal(started.demo, true);
      assert.equal(started.phone.state, 'connected');
      assert.equal(started.phone.connections, 2);
      assert.deepEqual(started.last_stop, { reason: null, at: null });
      assert.equal(started.last_stop_message, null);

      await assert.rejects(client.call('start', { mode: 'phone', ping: false }), (error) => {
        assert.equal(error.code, 'engine_error');
        assert.equal(error.message, 'The service could not start. Check the settings.');
        assert.equal(error.status, 400);
        return true;
      });

      await assert.rejects(client.call('forget'), (error) => {
        assert.equal(error.code, 'forget_blocked');
        assert.equal(error.message, 'Turn off the tunnel first.');
        assert.equal(error.status, 409);
        return true;
      });
    });

    await t.test('diagnostics and activity keep the running contract', async () => {
      const diagnostics = await client.call('diagnostics');
      assertDiagnosticsShape(diagnostics);
      assert.equal(diagnostics.running, true);
      assert.ok(diagnostics.engine.uptime_s >= 0);

      const activity = await client.call('activity', { since: 0 });
      assert.ok(Array.isArray(activity.logs));
      assert.ok(activity.logs.length > 0, 'the start logged at least one entry');
      assert.ok(Number.isInteger(activity.next) && activity.next >= 0);
      for (const entry of activity.logs) {
        assert.equal(JSON.stringify(entry).includes(SECRET), false);
      }
    });

    await t.test('stop is idempotent and reports the real stopped envelope', async () => {
      const stopped = await client.call('stop');
      assertStatusShape(stopped);
      assert.equal(stopped.running, false);
      assert.equal(stopped.mode, null);
      assert.equal(stopped.icmp_enabled, false);
      assert.equal(stopped.demo, true);
      assert.deepEqual(stopped.last_stop.reason, 'user');
      assert.equal(typeof stopped.last_stop.at, 'number');
      assert.equal(stopped.last_stop_message, null);

      const again = await client.call('stop');
      assert.equal(again.running, false);
      assert.equal(again.demo, true);
    });

    await t.test('direct mode starts through the fixed contract and needs no source device', async () => {
      /* The client maps { mode: 'direct' } to the engine's fixed `tun` start
       * with IPv6 blocked. This runs against the in-memory demo backend: no
       * TUN device, route, or privilege is involved. */
      const started = await client.call('start', { mode: 'direct', ping: true });
      assertStatusShape(started);
      assert.equal(started.running, true);
      assert.equal(started.mode, 'tun');
      assert.equal(started.demo, true);
      /* The echo relay belongs to source device proxy mode only. */
      assert.equal(started.icmp_enabled, false);
      assert.deepEqual(started.last_stop, { reason: null, at: null });
      assert.equal(JSON.stringify(started).includes(SECRET), false);

      const running = await client.call('status');
      assert.equal(running.running, true);
      assert.equal(running.mode, 'tun');

      /* A second start is refused with the same fixed envelope as phone mode. */
      await assert.rejects(client.call('start', { mode: 'direct' }), (error) => {
        assert.equal(error.code, 'engine_error');
        assert.equal(error.status, 400);
        return true;
      });

      const stopped = await client.call('stop');
      assert.equal(stopped.running, false);
      assert.equal(stopped.mode, null);
      assert.equal(stopped.last_stop.reason, 'user');
    });

    await t.test('the client refuses a start mode outside the fixed list', async () => {
      for (const mode of ['tun', 'socks5', '', 'Direct', 5, null]) {
        await assert.rejects(client.call('start', { mode: mode }), (error) => {
          assert.equal(error.code, 'invalid_request');
          return true;
        });
      }
      const status = await client.call('status');
      assert.equal(status.running, false);
    });

    await t.test('diagnostics and failures keep the stopped contract', async () => {
      const diagnostics = await client.call('diagnostics');
      assertDiagnosticsShape(diagnostics);
      assert.equal(diagnostics.running, false);
      assert.equal(diagnostics.setup.connect_ms.count, 0);
      assert.deepEqual(diagnostics.failures, { total: 0, dropped: 0 });

      const failures = await client.call('failures');
      assert.equal(failures.ok, true);
      assert.equal(failures.demo, true);
      assert.ok(Number.isInteger(failures.total));
      assert.ok(Number.isInteger(failures.dropped));
      assert.ok(Array.isArray(failures.groups));
      assert.ok(Array.isArray(failures.recent));
      assert.equal(JSON.stringify(failures).includes(SECRET), false);
    });

    await t.test('unknown routes and invalid bodies return the fixed error envelopes', async () => {
      const auth = { Authorization: 'Bearer ' + SECRET };

      const missing = await requestRaw(engine.port, {
        path: '/api/does-not-exist',
        headers: auth
      });
      assert.deepEqual(assertJsonResponse(missing, 404), {
        ok: false,
        error: 'not found'
      });

      const noType = await requestRaw(engine.port, {
        method: 'POST',
        path: '/api/start',
        headers: auth
      });
      assert.deepEqual(assertJsonResponse(noType, 415), {
        ok: false,
        error: 'unsupported media type: POST requires application/json'
      });

      const badJson = await requestRaw(engine.port, {
        method: 'POST',
        path: '/api/start',
        headers: Object.assign({}, auth, { 'Content-Type': 'application/json' }),
        body: '{'
      });
      assert.deepEqual(assertJsonResponse(badJson, 400), {
        ok: false,
        error: 'request body must be valid JSON'
      });

      const notObject = await requestRaw(engine.port, {
        method: 'POST',
        path: '/api/start',
        headers: Object.assign({}, auth, { 'Content-Type': 'application/json' }),
        body: '[]'
      });
      assert.deepEqual(assertJsonResponse(notObject, 400), {
        ok: false,
        error: 'request body must be a JSON object'
      });
    });

    await t.test('closing the parent liveness descriptor exits cleanly', async () => {
      assert.ok(engine.child.stdio && engine.child.stdio[4], 'the parent pipe exists');
      assert.equal(engine.exitInfo(), null);
      engine.child.stdio[4].destroy();
      const exit = await within(
        engine.exited,
        EXIT_TIMEOUT_MS,
        'The engine did not exit after the parent descriptor closed.'
      );
      assert.deepEqual(exit, { code: 0, signal: null });
      assert.equal(fs.existsSync(engine.portFile), false, 'the port file is removed on exit');
      assert.equal(fs.existsSync(engine.portFileTemp), false, 'the temporary port file is removed');
      assert.equal(/panicked at/.test(engine.output()), false, 'the engine did not panic');
    });
  } finally {
    await closeEngine(engine);
  }
});
