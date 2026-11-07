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

/* The engine client side of the Linux pairing handoff. The user engine gets
 * its handoff socket on descriptor 0 and a private HOME. The privileged launch
 * passes that socket to pkexec as descriptor 2 and sends HS2. No real engine,
 * helper, pkexec, or privilege is used. */

const require = createRequire(import.meta.url);
const { createEngineClient, userEngineHome, OPERATIONS } = require('../src/backend/engine-client.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const fakeHelper = path.join(here, 'fixtures', 'fake-helper.js');

function tools() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-handoff-'));
  const make = (name) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    return file;
  };
  return {
    directory,
    pkexec: make('pkexec'),
    helper: make('hotspotshade-helper'),
    engine: make('hotspotshade'),
    remove() { fs.rmSync(directory, { recursive: true, force: true }); }
  };
}

test('the user engine data directory follows XDG_DATA_HOME and ignores a relative value', () => {
  assert.equal(userEngineHome({ XDG_DATA_HOME: '/data/me' }, '/home/me'), '/data/me/hotspotshade/engine');
  assert.equal(userEngineHome({ XDG_DATA_HOME: 'relative' }, '/home/me'), '/home/me/.local/share/hotspotshade/engine');
  assert.equal(userEngineHome({}, '/home/me'), '/home/me/.local/share/hotspotshade/engine');
});

test('the handoff operation is one fixed POST with an empty body', () => {
  assert.deepEqual({ ...OPERATIONS.handoff }, { method: 'POST', path: '/api/pairing/handoff', timeoutMs: 5000 });
});

test('the user engine gets the handoff socket on descriptor 0 and a private HOME', async () => {
  const t = tools();
  const home = path.join(t.directory, 'data', 'hotspotshade', 'engine');
  const calls = [];
  const child = new EventEmitter();
  child.pid = 5151;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new PassThrough();
  child.stdio = [child.stdin, child.stdout, child.stderr, new PassThrough(), new PassThrough()];
  child.kill = () => { setImmediate(() => child.emit('exit', 0, null)); return true; };
  const client = createEngineClient({
    executable: t.engine,
    handoff: true,
    home,
    startTimeoutMs: 300,
    spawn(command, args, options) {
      calls.push({ command, args, options });
      return child;
    }
  });
  try {
    await assert.rejects(client.start(), (error) => error.code === 'engine_start_timeout');
    assert.equal(calls.length, 1);
    const { args, options } = calls[0];
    assert.deepEqual(args.slice(-2), ['--handoff-fd', '0']);
    assert.equal(options.stdio[0], 'pipe', 'Node creates the socket and never reads a child stdin');
    assert.equal(options.env.HOME, home);
    assert.equal(fs.statSync(home).mode & 0o777, 0o700);
    assert.doesNotMatch(JSON.stringify(args), /[0-9a-f]{64}/);
  } finally {
    await client.dispose();
    t.remove();
  }
});

test('a client without the handoff option keeps stdin closed and exposes no socket', async () => {
  const t = tools();
  let seen = null;
  const child = new EventEmitter();
  child.pid = 5152;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdio = [null, child.stdout, child.stderr, new PassThrough(), new PassThrough()];
  child.kill = () => { setImmediate(() => child.emit('exit', 0, null)); return true; };
  const client = createEngineClient({
    executable: t.engine,
    startTimeoutMs: 200,
    spawn(command, args, options) { seen = { args, options }; return child; }
  });
  try {
    await assert.rejects(client.start());
    assert.equal(seen.options.stdio[0], 'ignore');
    assert.equal(seen.args.includes('--handoff-fd'), false);
    assert.equal(client.handoffStream, null);
  } finally {
    await client.dispose();
    t.remove();
  }
});

/* A real socket from Node's child stdin, standing in for the user engine's
 * handoff socket. The holder process only sleeps. */
function holderSocket() {
  const holder = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: ['pipe', 'ignore', 'ignore'] });
  holder.stdin.on('error', () => {});
  return holder;
}

test('a privileged launch with a handoff sends HS2 and passes the socket as descriptor 2', async () => {
  const t = tools();
  const holder = holderSocket();
  const versionFile = path.join(t.directory, 'version');
  const calls = [];
  const client = createEngineClient({
    privileged: true,
    pkexecPath: t.pkexec,
    helperPath: t.helper,
    enginePath: t.engine,
    handoffStream: holder.stdin,
    startTimeoutMs: 5000,
    helperExitMs: 3000,
    spawn(command, args, options) {
      calls.push({ command, args, stdio: options.stdio });
      return spawn(process.execPath, [fakeHelper, ...args], Object.assign({}, options, {
        env: Object.assign({}, options.env, { HS_FAKE_HELPER_VERSION_FILE: versionFile })
      }));
    }
  });
  try {
    await client.call('status');
    assert.deepEqual(calls[0].args, [t.helper], 'pkexec still gets the helper path and nothing else');
    assert.equal(calls[0].stdio[2], holder.stdin, 'the handoff socket is descriptor 2 of pkexec');
    assert.equal(fs.readFileSync(versionFile, 'utf8'), 'HS2 socket');
    const result = await client.stop();
    assert.equal(result.stopped, true);
  } finally {
    await client.dispose();
    holder.kill('SIGTERM');
    t.remove();
  }
});

test('a privileged launch without a handoff keeps HS1 and a stderr pipe', async () => {
  const t = tools();
  const versionFile = path.join(t.directory, 'version');
  const calls = [];
  const client = createEngineClient({
    privileged: true,
    pkexecPath: t.pkexec,
    helperPath: t.helper,
    enginePath: t.engine,
    startTimeoutMs: 5000,
    helperExitMs: 3000,
    spawn(command, args, options) {
      calls.push({ stdio: options.stdio });
      return spawn(process.execPath, [fakeHelper, ...args], Object.assign({}, options, {
        env: Object.assign({}, options.env, { HS_FAKE_HELPER_VERSION_FILE: versionFile })
      }));
    }
  });
  try {
    await client.call('status');
    assert.deepEqual(calls[0].stdio, ['pipe', 'pipe', 'pipe']);
    assert.equal(fs.readFileSync(versionFile, 'utf8'), 'HS1');
  } finally {
    await client.dispose();
    t.remove();
  }
});

test('with a handoff, a helper reason line on stdout still gives the plain message', async () => {
  const t = tools();
  const holder = holderSocket();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: t.pkexec,
    helperPath: t.helper,
    enginePath: t.engine,
    handoffStream: holder.stdin,
    startTimeoutMs: 5000,
    spawn(command, args, options) {
      return spawn(process.execPath, [fakeHelper, ...args], Object.assign({}, options, {
        env: Object.assign({}, options.env, {
          HS_FAKE_HELPER_EXIT_BEFORE_READY: '1',
          HS_FAKE_HELPER_REASON: 'HS_REASON engine_missing'
        })
      }));
    }
  });
  try {
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /packaged engine/i);
      assert.match(error.message, /missing or not executable/i);
      return true;
    });
  } finally {
    await client.dispose();
    holder.kill('SIGTERM');
    t.remove();
  }
});
