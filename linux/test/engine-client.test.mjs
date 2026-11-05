import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  createEngineHttpClient,
  resolveEngineConfig
} = require('../src/backend/engine-client.js');
const { createEngineBackend } = require('../src/backend/engine-backend.js');

const SECRET = 'ab'.repeat(32);

function collectBody(request) {
  return new Promise((resolve) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function fakeEngine(handler) {
  const requests = [];
  const server = http.createServer((request, response) => {
    collectBody(request).then((body) => {
      requests.push({
        method: request.method,
        url: request.url,
        headers: request.headers,
        body
      });
      handler(request, response, body);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    requests,
    close() {
      return new Promise((resolve) => server.close(resolve));
    }
  };
}

function reply(response, statusCode, value) {
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  response.writeHead(statusCode, { 'Content-Type': 'application/json' });
  response.end(body);
}

function temporaryExecutable() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-config-'));
  const file = path.join(directory, 'hotspotshade');
  fs.writeFileSync(file, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  return { directory, file };
}

test('the engine setting is explicit and an absolute path', () => {
  const temporary = temporaryExecutable();
  try {
    const demoDefault = resolveEngineConfig({ argv: ['electron', '.'], env: {} });
    assert.equal(demoDefault.mode, 'demo');
    assert.equal(demoDefault.executable, '');

    const fromEnv = resolveEngineConfig({ argv: ['electron', '.'], env: { HOTSPOTSHADE_ENGINE: temporary.file } });
    assert.equal(fromEnv.mode, 'engine');
    assert.equal(fromEnv.executable, temporary.file);
    assert.equal(fromEnv.demo, false);

    const fromArgument = resolveEngineConfig({
      argv: ['electron', '.', '--engine=' + temporary.file],
      env: { HOTSPOTSHADE_ENGINE: '/should/not/win' }
    });
    assert.equal(fromArgument.executable, temporary.file);

    const engineDemo = resolveEngineConfig({
      argv: ['electron', '.', '--engine', temporary.file],
      env: { HOTSPOTSHADE_ENGINE_DEMO: '1' }
    });
    assert.equal(engineDemo.mode, 'engine');
    assert.equal(engineDemo.demo, true);

    const forcedDemo = resolveEngineConfig({
      argv: ['electron', '.', '--demo', '--engine', temporary.file],
      env: { HOTSPOTSHADE_ENGINE: temporary.file }
    });
    assert.equal(forcedDemo.mode, 'demo');
    assert.equal(forcedDemo.executable, '');

    const relative = resolveEngineConfig({ argv: ['electron', '.'], env: { HOTSPOTSHADE_ENGINE: 'hotspotshade' } });
    assert.equal(relative.mode, 'error');
    assert.match(relative.error, /absolute/);

    const bareName = resolveEngineConfig({ argv: ['electron', '.', '--engine', 'hotspotshade'] });
    assert.equal(bareName.mode, 'error');
    assert.match(bareName.error, /PATH/);

    const missing = resolveEngineConfig({ argv: ['electron', '.', '--engine', '/no/such/hotspotshade'] });
    assert.equal(missing.mode, 'error');
    assert.match(missing.error, /missing/i);

    const empty = resolveEngineConfig({ argv: ['electron', '.', '--engine='] });
    assert.equal(empty.mode, 'error');

    const noValue = resolveEngineConfig({ argv: ['electron', '.', '--engine'] });
    assert.equal(noValue.mode, 'error');
  } finally {
    fs.rmSync(temporary.directory, { recursive: true, force: true });
  }
});

test('the HTTP boundary sends only the fixed operations', async () => {
  const engine = await fakeEngine((request, response) => {
    if (request.url === '/api/status') {
      reply(response, 200, { demo: true, running: false, paired: false });
      return;
    }
    if (request.url === '/api/phone/pair') {
      reply(response, 200, { state: request.method === 'POST' ? 'paired' : 'idle', code: null, error: null });
      return;
    }
    if (request.url === '/api/phone/pair/cancel') {
      reply(response, 200, { state: 'idle', code: null, error: null });
      return;
    }
    if (request.url === '/api/phone/forget') {
      reply(response, 200, { ok: true });
      return;
    }
    if (request.url === '/api/phone/probe') {
      reply(response, 200, { ok: true, phone: { state: 'ready' } });
      return;
    }
    if (request.url === '/api/start') {
      reply(response, 200, { ok: true, status: { running: true, paired: true }, result: {} });
      return;
    }
    if (request.url === '/api/stop') {
      reply(response, 200, { ok: true, status: { running: false, last_stop_message: 'You turned the tunnel off.' }, result: {} });
      return;
    }
    if (request.url === '/api/failures') {
      reply(response, 200, { ok: true, total: 0, groups: [], recent: [] });
      return;
    }
    if (request.url === '/api/diagnostics') {
      reply(response, 200, { ok: true, running: false, demo: true });
      return;
    }
    if (request.url === '/api/logs?since=7') {
      reply(response, 200, { logs: [{ seq: 8, msg: 'one' }], next: 8 });
      return;
    }
    reply(response, 404, { ok: false, error: 'not found' });
  });
  try {
    const client = createEngineHttpClient({ port: engine.port, secret: SECRET });
    assert.deepEqual(await client.call('status'), { demo: true, running: false, paired: false });
    assert.deepEqual(await client.call('pairState'), { state: 'idle', code: null, error: null });
    assert.deepEqual(await client.call('pair'), { state: 'paired', code: null, error: null });
    assert.deepEqual(await client.call('pairCancel'), { state: 'idle', code: null, error: null });
    assert.deepEqual(await client.call('forget'), { ok: true });
    assert.deepEqual(await client.call('probe'), { ok: true, phone: { state: 'ready' } });
    assert.deepEqual(await client.call('start', { ping: true }), { running: true, paired: true });
    assert.deepEqual(await client.call('stop'), { running: false, last_stop_message: 'You turned the tunnel off.' });
    assert.deepEqual(await client.call('failures'), { ok: true, total: 0, groups: [], recent: [] });
    assert.deepEqual(await client.call('diagnostics'), { ok: true, running: false, demo: true });
    assert.deepEqual(await client.call('activity', { since: 7 }), { logs: [{ seq: 8, msg: 'one' }], next: 8 });

    const methods = engine.requests.map((entry) => entry.method + ' ' + entry.url);
    assert.deepEqual(methods, [
      'GET /api/status',
      'GET /api/phone/pair',
      'POST /api/phone/pair',
      'POST /api/phone/pair/cancel',
      'POST /api/phone/forget',
      'POST /api/phone/probe',
      'POST /api/start',
      'POST /api/stop',
      'GET /api/failures',
      'GET /api/diagnostics',
      'GET /api/logs?since=7'
    ]);
    for (const entry of engine.requests) {
      assert.equal(entry.headers.authorization, 'Bearer ' + SECRET);
      assert.equal(entry.headers.host, '127.0.0.1:' + engine.port);
      assert.equal(entry.headers.origin, undefined);
    }
    const start = engine.requests.find((entry) => entry.url === '/api/start');
    assert.equal(start.body, '{"mode":"phone","options":{"experimental_icmp":true}}');
    assert.equal(engine.requests.find((entry) => entry.url === '/api/phone/forget').body, '{}');
  } finally {
    await engine.close();
  }
});

test('unknown operations and invalid activity values never reach the engine', async () => {
  const engine = await fakeEngine((request, response) => reply(response, 200, {}));
  try {
    const client = createEngineHttpClient({ port: engine.port, secret: SECRET });
    await assert.rejects(client.call('openUrl'), { code: 'invalid_request' });
    await assert.rejects(client.call('/api/status'), { code: 'invalid_request' });
    await assert.rejects(client.call('activity', { since: -1 }), { code: 'invalid_request' });
    await assert.rejects(client.call('activity', { since: 1.5 }), { code: 'invalid_request' });
    assert.equal(engine.requests.length, 0);
  } finally {
    await engine.close();
  }
});

test('engine errors become plain errors with fixed codes', async () => {
  const cases = [];
  async function one(handler, run) {
    const engine = await fakeEngine(handler);
    try {
      const client = createEngineHttpClient({ port: engine.port, secret: SECRET });
      await run(client);
    } finally {
      await engine.close();
    }
  }

  await one((request, response) => reply(response, 401, { ok: false, error: 'unauthorized' }), async (client) => {
    await assert.rejects(client.call('status'), (error) => {
      cases.push(error.code);
      assert.equal(error.code, 'engine_unauthorized');
      assert.equal(error.message, 'The engine rejected the request.');
      return true;
    });
  });
  await one((request, response) => reply(response, 404, { ok: false, error: 'not found' }), async (client) => {
    await assert.rejects(client.call('failures'), { code: 'not_supported' });
  });
  await one((request, response) => reply(response, 409, { ok: false, error: 'Turn off the tunnel first.' }), async (client) => {
    await assert.rejects(client.call('forget'), (error) => {
      assert.equal(error.code, 'forget_blocked');
      assert.equal(error.message, 'Turn off the tunnel first.');
      return true;
    });
  });
  await one((request, response) => reply(response, 409, { ok: false, code: 'phone_token_rejected', error: 'Pair again.' }), async (client) => {
    await assert.rejects(client.call('start', { ping: true }), (error) => {
      assert.equal(error.code, 'phone_token_rejected');
      assert.equal(error.message, 'Pair again.');
      return true;
    });
  });
  await one((request, response) => reply(response, 200, { ok: false, error: 'The service could not start.' }), async (client) => {
    await assert.rejects(client.call('start', { ping: false }), (error) => {
      assert.equal(error.code, 'engine_error');
      assert.equal(error.message, 'The service could not start.');
      return true;
    });
  });
  await one((request, response) => reply(response, 200, 'not json'), async (client) => {
    await assert.rejects(client.call('status'), { code: 'engine_bad_response' });
  });
  await one((request, response) => reply(response, 500, '<html>no</html>'), async (client) => {
    await assert.rejects(client.call('status'), (error) => {
      assert.equal(error.code, 'engine_error');
      assert.equal(error.message, 'The engine request failed.');
      return true;
    });
  });
  assert.deepEqual(cases, ['engine_unauthorized']);
});

test('a response over the size limit is refused', async () => {
  const engine = await fakeEngine((request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ ok: true, blob: 'x'.repeat(1024 * 1024 + 10) }));
  });
  try {
    const client = createEngineHttpClient({ port: engine.port, secret: SECRET });
    await assert.rejects(client.call('status'), { code: 'engine_response_too_large' });
  } finally {
    await engine.close();
  }
});

test('the backend maps the fixed methods and never adds a path or secret', async () => {
  const calls = [];
  const client = {
    call(operation, params) {
      calls.push([operation, params]);
      return Promise.resolve({ operation: operation });
    },
    describe() {
      return { connected: true, transport: 'loopback_http', tunnel: 'engine_service', operations: [] };
    },
    stop() {
      calls.push(['stop-client']);
      return Promise.resolve();
    }
  };
  const backend = createEngineBackend({ client });
  assert.equal(backend.mode, 'engine');
  assert.deepEqual(await backend.status(), { operation: 'status' });
  assert.deepEqual(await backend.pairState(), { operation: 'pairState' });
  assert.deepEqual(await backend.beginPairing(), { operation: 'pair' });
  assert.deepEqual(await backend.cancelPairing(), { operation: 'pairCancel' });
  assert.deepEqual(await backend.forget(), { operation: 'forget' });
  assert.deepEqual(await backend.start({ ping: true }), { operation: 'start' });
  assert.deepEqual(await backend.stop(), { operation: 'stop' });
  assert.deepEqual(await backend.probe(), { operation: 'probe' });
  assert.deepEqual(await backend.activity({ since: 3 }), { operation: 'activity' });
  assert.deepEqual(await backend.failures(), { operation: 'failures' });
  assert.deepEqual(await backend.diagnostics(), { operation: 'diagnostics' });
  assert.throws(() => backend.applyScenario('ready'), { code: 'demo_only' });
  await backend.dispose();
  assert.deepEqual(calls, [
    ['status', undefined],
    ['pairState', undefined],
    ['pair', undefined],
    ['pairCancel', undefined],
    ['forget', undefined],
    ['start', { ping: true }],
    ['stop', undefined],
    ['probe', undefined],
    ['activity', { since: 3 }],
    ['failures', undefined],
    ['diagnostics', undefined],
    ['stop-client']
  ]);
});
