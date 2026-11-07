import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
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
    parentCloseMs: 2000
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
    const started = await client.call('start', { mode: 'phone', ping: true });
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

/* Write a small engine script that writes a port file and then runs the given
 * statements. It needs no HTTP server because the client only reads the port. */
function scriptedEngine(name, statements) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-' + name + '-'));
  const script = path.join(directory, name + '.js');
  fs.writeFileSync(script, [
    "'use strict';",
    "const fs = require('node:fs');",
    "const args = process.argv.slice(2);",
    "const portFile = args[args.indexOf('--port-file') + 1];",
    "fs.writeFileSync(portFile, '49152\\n', { mode: 0o600 });",
    ...statements,
    ''
  ].join('\n'));
  return { directory, script };
}

/* An engine that ignores the graceful signals and never reads the liveness
 * descriptor. It is a stand-in for a stuck engine. */
function stubbornEngine() {
  return scriptedEngine('stubborn-engine', [
    "process.on('SIGTERM', function () {});",
    "process.on('SIGINT', function () {});",
    "setInterval(function () {}, 1000);"
  ]);
}

function stopBudgets() {
  return { startTimeoutMs: 5000, stopGraceMs: 100, parentCloseMs: 100 };
}

/* A fake development engine child whose streams exist and whose pid the test
 * controls. It never exits unless the test emits `exit`, so a signaling error
 * can be ordered against a still-live process. */
function fakeLiveEngineChild(pid = 4501) {
  const child = new EventEmitter();
  child.pid = pid;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new PassThrough();
  const tokenStream = new PassThrough();
  const parentStream = new PassThrough();
  child.stdio = [child.stdin, child.stdout, child.stderr, tokenStream, parentStream];
  child.signals = [];
  child.kill = function (signal) {
    child.signals.push(signal === undefined ? 'default' : signal);
    return true;
  };
  return child;
}

test('a signaling error keeps the live pid and never claims the engine never started', async () => {
  const child = fakeLiveEngineChild();
  child.kill = function (signal) {
    child.signals.push(signal === undefined ? 'default' : signal);
    /* A failed signal is reported as a child `error`, not as an exit. */
    queueMicrotask(function () {
      child.emit('error', new Error('the stop signal could not be delivered'));
    });
    return false;
  };
  const client = createEngineClient(Object.assign({
    executable: process.execPath,
    spawn() {
      return child;
    }
  }, stopBudgets()));
  try {
    const starting = client.start();
    assert.equal(await waitFor(() => client.tempDirectory !== null), true);
    fs.writeFileSync(path.join(client.tempDirectory, 'port'), '49152\n', { mode: 0o600 });
    await starting;
    assert.equal(client.isRunning(), true);
    assert.equal(client.pid, child.pid);

    const result = await client.stop();
    assert.deepEqual(child.signals, ['SIGTERM'], 'the app sends only the graceful signal');
    assert.equal(client.exitInfo(), null, 'no exit was observed');
    assert.equal(client.pid, child.pid, 'the live pid is not lost');
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      stillRunning: true,
      failed: true,
      cleanupUnconfirmed: true,
      reason: 'engine_still_running'
    });
    assert.equal(Object.hasOwn(result, 'neverStarted'), false);
    assert.equal(result.reason === 'engine_start_failed', false);
  } finally {
    await client.dispose();
  }
});

test('an error before the child exists is a spawn failure with no live pid', async () => {
  const child = fakeLiveEngineChild();
  child.pid = undefined;
  const client = createEngineClient(Object.assign({
    executable: process.execPath,
    spawn() {
      return child;
    }
  }, stopBudgets()));
  try {
    const starting = client.start().catch((error) => error);
    queueMicrotask(function () {
      child.emit('error', new Error('spawn ENOENT'));
    });
    const error = await starting;
    assert.equal(error.code, 'engine_start_failed');
    assert.equal(client.pid, null);
    const info = client.exitInfo();
    assert.equal(info.error, true);
    assert.equal(info.spawn, true, 'the failed spawn is distinguished from a signaling error');

    const result = await client.dispose();
    assert.deepEqual(result, {
      stopped: true,
      timedOut: false,
      neverStarted: true,
      reason: 'engine_start_failed'
    });
    assert.deepEqual(child.signals, [], 'no signal is sent to a child that never existed');
  } finally {
    await client.dispose();
  }
});

test('a development engine that ignores the graceful stop is left running without a forced kill', async () => {
  const stub = stubbornEngine();
  const signals = [];
  let real = null;
  const client = createEngineClient(Object.assign({
    executable: process.execPath,
    argvPrefix: [stub.script],
    spawn(command, args, options) {
      real = spawn(command, args, options);
      return new Proxy(real, {
        get(target, property) {
          if (property === 'kill') {
            return (signal) => {
              signals.push(signal);
              return target.kill(signal);
            };
          }
          const value = target[property];
          return typeof value === 'function' ? value.bind(target) : value;
        }
      });
    }
  }, stopBudgets()));
  try {
    await client.start();
    const pid = client.pid;
    assert.ok(pid > 0);
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      stillRunning: true,
      failed: true,
      cleanupUnconfirmed: true,
      reason: 'engine_still_running'
    });
    assert.deepEqual(signals, ['SIGTERM'], 'the app sends only the graceful signal');
    assert.equal(client.exitInfo(), null, 'the engine is still alive');
    assert.equal(client.isRunning(), false);
    assert.equal(JSON.stringify(result).includes('helper'), false);
    /* The client refuses a restart while the old engine may still run. */
    await assert.rejects(client.start(), { code: 'engine_stopped' });
    /* A later stop returns the same answer and sends no more signals. */
    assert.equal(await client.stop(), result);
    assert.deepEqual(signals, ['SIGTERM']);
  } finally {
    if (real) {
      /* Test cleanup only. The app never sends this signal. */
      try {
        real.kill('SIGKILL');
      } catch (error) {
        /* The test engine is already gone. */
      }
      await waitFor(() => client.exitInfo() !== null, 2000);
    }
    await client.dispose();
    fs.rmSync(stub.directory, { recursive: true, force: true });
  }
});

test('a graceful stop of the development engine reports no forced kill', async () => {
  const client = engineClient();
  try {
    await client.call('status');
    const result = await client.stop();
    assert.deepEqual(result, { stopped: true, timedOut: false });
  } finally {
    await client.dispose();
  }
});

test('a development engine that exits non-zero before stop reports unconfirmed cleanup', async () => {
  const stub = scriptedEngine('failing-engine', [
    "setTimeout(function () { process.exit(9); }, 150);",
    "setInterval(function () {}, 1000);"
  ]);
  const client = createEngineClient({
    executable: process.execPath,
    argvPrefix: [stub.script],
    startTimeoutMs: 5000,
    stopGraceMs: 200,
    parentCloseMs: 200
  });
  try {
    await client.start();
    assert.equal(await waitFor(() => client.exitInfo() !== null, 3000), true);
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      failed: true,
      reason: 'engine_failed',
      cleanupUnconfirmed: true
    });
  } finally {
    await client.dispose();
    fs.rmSync(stub.directory, { recursive: true, force: true });
  }
});

test('a development engine that exits on a signal before stop reports unconfirmed cleanup', async () => {
  const stub = scriptedEngine('signaled-engine', [
    "setTimeout(function () { process.kill(process.pid, 'SIGTERM'); }, 150);",
    "setInterval(function () {}, 1000);"
  ]);
  const client = createEngineClient({
    executable: process.execPath,
    argvPrefix: [stub.script],
    startTimeoutMs: 5000,
    stopGraceMs: 200,
    parentCloseMs: 200
  });
  try {
    await client.start();
    assert.equal(await waitFor(() => client.exitInfo() !== null, 3000), true);
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      failed: true,
      reason: 'engine_signaled',
      cleanupUnconfirmed: true
    });
  } finally {
    await client.dispose();
    fs.rmSync(stub.directory, { recursive: true, force: true });
  }
});

test('a development engine that dies on the stop SIGTERM reports unconfirmed cleanup', async () => {
  /* No SIGTERM handler: Node exits on the signal without running the engine
   * route cleanup. */
  const stub = scriptedEngine('term-engine', [
    "setInterval(function () {}, 1000);"
  ]);
  const client = createEngineClient({
    executable: process.execPath,
    argvPrefix: [stub.script],
    startTimeoutMs: 5000,
    stopGraceMs: 2000,
    parentCloseMs: 200
  });
  try {
    await client.start();
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      failed: true,
      reason: 'engine_signaled',
      cleanupUnconfirmed: true
    });
    assert.equal(client.exitInfo().signal, 'SIGTERM');
  } finally {
    await client.dispose();
    fs.rmSync(stub.directory, { recursive: true, force: true });
  }
});

test('a development engine that exited cleanly before stop is a clean stop', async () => {
  const stub = scriptedEngine('clean-engine', [
    "setTimeout(function () { process.exit(0); }, 150);",
    "setInterval(function () {}, 1000);"
  ]);
  const client = createEngineClient({
    executable: process.execPath,
    argvPrefix: [stub.script],
    startTimeoutMs: 5000,
    stopGraceMs: 200,
    parentCloseMs: 200
  });
  try {
    await client.start();
    assert.equal(await waitFor(() => client.exitInfo() !== null, 3000), true);
    const result = await client.stop();
    assert.deepEqual(result, { stopped: true, timedOut: false });
  } finally {
    await client.dispose();
    fs.rmSync(stub.directory, { recursive: true, force: true });
  }
});
