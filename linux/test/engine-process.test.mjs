import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createEngineClient } = require('../src/backend/engine-client.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'fixtures', 'fake-engine.js');

function engineClient(extra = {}) {
  return createEngineClient(Object.assign({
    executable: process.execPath,
    argvPrefix: [fixture],
    startTimeoutMs: 5000,
    stopGraceMs: 1000,
    parentCloseMs: 2000,
    killWaitMs: 500
  }, extra));
}

async function waitFor(predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

test('the client starts one fake engine and stops it with SIGTERM', async () => {
  const client = engineClient();
  try {
    const status = await client.call('status');
    assert.equal(status.demo, true);
    assert.equal(status.running, false);
    assert.ok(client.pid > 0);
    assert.equal(client.isRunning(), true);
    assert.equal(client.describe().connected, true);
    assert.equal(client.describe().transport, 'loopback_http');

    const directory = client.tempDirectory;
    assert.ok(directory, 'the private temporary directory exists');
    assert.ok(fs.existsSync(directory));
    const mode = fs.statSync(directory).mode & 0o777;
    assert.equal(mode, 0o700);

    const pair = await client.call('pair');
    assert.equal(pair.state, 'paired');
    const started = await client.call('start', { ping: true });
    assert.equal(started.running, true);
    assert.equal(started.icmp_enabled, true);
    const stopped = await client.call('stop');
    assert.equal(stopped.running, false);
    assert.equal(stopped.last_stop_message, 'You turned the tunnel off.');

    await client.stop();
    assert.equal(client.isRunning(), false);
    assert.equal(client.describe().connected, false);
    assert.equal(fs.existsSync(directory), false, 'the temporary directory is removed');
    assert.equal(client.exitInfo().code, 0);
    assert.equal(client.exitInfo().signal, null);
  } finally {
    await client.dispose();
  }
});

test('the engine stops when the parent-liveness descriptor closes', async () => {
  const client = engineClient({ argvPrefix: [fixture, '--ignore-sigterm'], stopGraceMs: 50, parentCloseMs: 3000 });
  try {
    await client.call('status');
    assert.equal(client.isRunning(), true);
    await client.stop();
    assert.equal(client.isRunning(), false);
    const info = client.exitInfo();
    assert.equal(info.code, 0, 'the engine exited cleanly after the liveness close');
    assert.equal(info.signal, null, 'the engine was not killed first');
  } finally {
    await client.dispose();
  }
});

test('a crashed engine becomes one plain error and never restarts', async () => {
  const client = engineClient();
  try {
    await client.call('status');
    const pid = client.pid;
    assert.ok(pid > 0);
    process.kill(pid, 'SIGKILL');
    assert.equal(await waitFor(() => !client.isRunning()), true);
    await assert.rejects(client.call('status'), (error) => {
      assert.equal(error.code, 'engine_stopped');
      assert.match(error.message, /^The engine stopped unexpectedly/);
      return true;
    });
    await assert.rejects(client.call('pairState'), { code: 'engine_stopped' });
    assert.equal(client.pid, null);
  } finally {
    await client.dispose();
  }
});

test('a missing or relative engine path is refused before spawn', async () => {
  const relative = createEngineClient({ executable: 'hotspotshade' });
  await assert.rejects(relative.start(), { code: 'engine_config' });
  await relative.stop();

  const missing = createEngineClient({ executable: '/no/such/hotspotshade' });
  await assert.rejects(missing.start(), { code: 'engine_config' });
  await missing.stop();
});

test('an engine that exits during startup reports a startup error', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-fail-'));
  const executable = path.join(directory, 'fail-engine');
  fs.writeFileSync(executable, '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  const client = createEngineClient({
    executable: executable,
    startTimeoutMs: 3000,
    stopGraceMs: 200
  });
  try {
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /startup/);
      return true;
    });
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /startup/);
      return true;
    });
  } finally {
    await client.dispose();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
