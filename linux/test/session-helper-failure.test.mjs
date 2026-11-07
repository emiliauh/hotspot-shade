import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

/* The real engine client with the fake helper (a script that stands in for
 * pkexec and the helper) feeding the real session backend. A user engine fake
 * stands in for the unprivileged engine. No real helper, engine, or privilege
 * runs. */

const require = createRequire(import.meta.url);
const {
  HELPER_REASON_MESSAGES,
  createEngineClient
} = require('../src/backend/engine-client.js');
const { createSessionBackend, confirmedStop } = require('../src/backend/session-backend.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'fixtures', 'fake-helper.js');

function temporaryTools() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-session-helper-'));
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

function fakeHelperSpawn(extraEnv) {
  return function (command, args, options) {
    const env = Object.assign({}, options.env, extraEnv);
    return spawn(process.execPath, [fixture, ...args], Object.assign({}, options, { env }));
  };
}

function fakeUser() {
  const calls = [];
  return {
    calls,
    handoffStream: null,
    async call(operation) {
      calls.push(operation);
      if (operation === 'status') return { source: 'user', running: false, paired: true, state: 'idle' };
      return { source: 'user', operation };
    },
    stop: async () => ({ stopped: true, timedOut: false }),
    describe: () => ({ connected: true, transport: 'loopback_http', operations: ['status'] })
  };
}

function sessionWithHelper(tools, helperEnv, clientOptions = {}) {
  const clients = [];
  const backend = createSessionBackend({
    userClient: fakeUser(),
    createRootClient() {
      const client = createEngineClient(Object.assign({
        privileged: true,
        pkexecPath: tools.pkexec,
        helperPath: tools.helper,
        enginePath: tools.engine,
        startTimeoutMs: 5000,
        authorizationTimeoutMs: 5000,
        authorizationStopMs: 200,
        helperExitMs: 3000,
        stdoutDrainMs: 1000,
        spawn: fakeHelperSpawn(helperEnv)
      }, clientOptions));
      clients.push(client);
      return client;
    }
  });
  return { backend, clients };
}

async function waitFor(predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

test('a helper exit 1 before readiness is a failed Turn on with no cleanup mark', async () => {
  const tools = temporaryTools();
  const { backend, clients } = sessionWithHelper(tools, {
    HS_FAKE_HELPER_EXIT_BEFORE_READY: '1',
    HS_FAKE_HELPER_REASON: 'HS_REASON engine_unsafe_permissions'
  });
  try {
    await assert.rejects(backend.start({ mode: 'direct' }), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.equal(error.message, HELPER_REASON_MESSAGES.engine_unsafe_permissions);
      return true;
    });
    const view = backend.session();
    assert.equal(view.cleanupPending, false, 'a helper that never spawned an engine leaves no mark');
    assert.equal(view.elevated, false, 'the app is back on the user engine');
    const status = await backend.status();
    assert.equal(status.source, 'user');
    assert.notEqual(status.cleanup_blocked, true);
    assert.notEqual(status.state, 'unknown');
    /* Nothing is pending, so a second Turn on is accepted and tries again. */
    await assert.rejects(backend.start({ mode: 'direct' }), (error) => error.code === 'engine_start_failed');
    assert.equal(clients.length, 2);
    assert.equal(confirmedStop(await clients[0].stop()), true);
    const quit = await backend.dispose();
    assert.equal(confirmedStop(quit), true);
  } finally {
    tools.remove();
  }
});

test('the client reports exit 1 before readiness as a clean never-started stop', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_BEFORE_READY: '1' })
  });
  try {
    await assert.rejects(client.start(), (error) => error.code === 'engine_start_failed');
    assert.deepEqual(await client.stop(), {
      stopped: true,
      timedOut: false,
      neverStarted: true,
      reason: 'helper_preparation_failed',
      helperCode: 1
    });
    assert.equal(client.engineSeen, false);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('exit 1 with no reason line before readiness shows the generic message and no mark', async () => {
  const tools = temporaryTools();
  const { backend } = sessionWithHelper(tools, { HS_FAKE_HELPER_EXIT_BEFORE_READY: '1' });
  try {
    await assert.rejects(backend.start({ mode: 'direct' }), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /could not prepare the engine start/i);
      return true;
    });
    assert.equal(backend.session().cleanupPending, false);
    assert.equal((await backend.status()).source, 'user');
  } finally {
    await backend.dispose();
    tools.remove();
  }
});

test('exit 1 after readiness with a known reason line (the start record) leaves no mark', async () => {
  const tools = temporaryTools();
  const { backend } = sessionWithHelper(tools, {
    HS_FAKE_HELPER_EXIT_AFTER_READY: '1',
    HS_FAKE_HELPER_REASON: 'HS_REASON state_write_failed'
  });
  try {
    await assert.rejects(backend.start({ mode: 'direct' }), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.equal(error.message, HELPER_REASON_MESSAGES.state_write_failed);
      return true;
    });
    assert.equal(backend.session().cleanupPending, false);
    assert.equal(backend.session().elevated, false);
  } finally {
    await backend.dispose();
    tools.remove();
  }
});

test('exit 1 after readiness with no reason line is not proof and keeps the cleanup mark', async () => {
  const tools = temporaryTools();
  const { backend } = sessionWithHelper(tools, { HS_FAKE_HELPER_EXIT_AFTER_READY: '1' });
  try {
    await assert.rejects(backend.start({ mode: 'direct' }), (error) => error.code === 'engine_start_failed');
    assert.equal(backend.session().cleanupPending, true);
    const status = await backend.status();
    /* The mark stays: the status is uncertain, never Off. */
    assert.equal(status.state, 'unknown');
    assert.equal(status.cleanup_blocked, true);
  } finally {
    await backend.dispose();
    tools.remove();
  }
});

test('exits after the spawn stay failed: exit 5 keeps the mark and names the engine code', async () => {
  const tools = temporaryTools();
  const { backend } = sessionWithHelper(tools, {
    HS_FAKE_HELPER_EXIT_AFTER_READY: '5',
    HS_FAKE_HELPER_REASON: 'HS_REASON listener_failed'
  });
  try {
    await assert.rejects(backend.start({ mode: 'direct' }), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.equal(error.message, HELPER_REASON_MESSAGES.listener_failed);
      return true;
    });
    assert.equal(backend.session().cleanupPending, true);
  } finally {
    await backend.dispose();
    tools.remove();
  }
});

test('every engine start-failure code has a plain message with no secret wording', () => {
  for (const code of [
    'arguments_invalid',
    'control_descriptor_invalid',
    'credentials_descriptor_invalid',
    'token_invalid',
    'credentials_handoff_invalid',
    'listener_failed',
    'port_file_failed',
    'credentials_import_failed'
  ]) {
    assert.ok(HELPER_REASON_MESSAGES[code].length > 40, code);
    assert.doesNotMatch(HELPER_REASON_MESSAGES[code], /secret|token/i, code);
  }
});

test('a helper that exits 0 after a stop timeout clears the mark on a status read', async () => {
  const tools = temporaryTools();
  const { backend } = sessionWithHelper(tools, {
    HS_FAKE_HELPER_STOP_TIMEOUT_DELAY_MS: '600',
    HS_FAKE_HELPER_EXIT_CODE: '0'
  });
  try {
    await backend.start({ mode: 'direct' });
    await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
    assert.equal(backend.session().cleanupPending, true);
    /* The real client throws on a stopped engine; the mark is still answered. */
    const marked = await backend.status();
    assert.equal(marked.cleanup_blocked, true);
    assert.equal(marked.state, 'unknown');
    /* No user action: the helper exits and the next status poll clears it. */
    let cleared = null;
    assert.equal(await waitFor(async () => {
      cleared = await backend.status().catch(() => null);
      return !!cleared && cleared.cleanup_blocked !== true;
    }), true);
    assert.equal(cleared.source, 'user');
    assert.equal(backend.session().cleanupPending, false);
    assert.equal(backend.session().elevated, false);
  } finally {
    await backend.dispose();
    tools.remove();
  }
});

test('a later Turn off re-attempts an unconfirmed stop and clears it once the helper has exited', async () => {
  const tools = temporaryTools();
  const { backend, clients } = sessionWithHelper(tools, {
    HS_FAKE_HELPER_STOP_TIMEOUT_DELAY_MS: '400',
    HS_FAKE_HELPER_EXIT_CODE: '0'
  });
  try {
    await backend.start({ mode: 'direct' });
    await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
    const first = await clients[0].stop();
    assert.equal(confirmedStop(first), false, 'the first result stays cached');
    assert.equal(await waitFor(() => clients[0].exitInfo() !== null), true);
    const second = await clients[0].retryStop();
    assert.notEqual(second, first, 'the retry classifies the helper state again');
    assert.equal(confirmedStop(second), true, 'the helper exit 0 after the timeout confirms the stop');
    const result = await backend.stop();
    assert.equal(result.running, false);
    assert.equal(backend.session().cleanupPending, false);
  } finally {
    await backend.dispose();
    tools.remove();
  }
});
