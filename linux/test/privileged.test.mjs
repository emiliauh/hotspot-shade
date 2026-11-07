import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  HELPER_REASON_MESSAGES,
  createEngineClient,
  helperReasonMessage,
  resolveEngineConfig
} = require('../src/backend/engine-client.js');
const {
  DEFAULT_ENGINE_PATH,
  DEFAULT_HELPER_PATH,
  DEFAULT_PKEXEC_PATH
} = require('../src/backend/engine-client.js');
const { createEngineBoundaryBackend } = require('../src/backend/engine-boundary.js');
const { createRouter } = require('../src/main/ipc.js');

const here = path.dirname(fileURLToPath(import.meta.url));
function read(relative) {
  return fs.readFileSync(path.join(here, '..', relative), 'utf8');
}
const fixture = path.join(here, 'fixtures', 'fake-helper.js');

function executable(directory, name, text = '#!/bin/sh\nexit 0\n') {
  const file = path.join(directory, name);
  fs.writeFileSync(file, text, { mode: 0o755 });
  return file;
}

function temporaryTools() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-privileged-'));
  return {
    directory,
    pkexec: executable(directory, 'pkexec'),
    helper: executable(directory, 'hotspotshade-helper'),
    helperDeny: executable(directory, 'deny-hotspotshade-helper'),
    engine: executable(directory, 'hotspotshade'),
    remove() {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  };
}

function privilegedEnv(tools) {
  return {
    HOTSPOTSHADE_PRIVILEGED: '1',
    HOTSPOTSHADE_PKEXEC: tools.pkexec,
    HOTSPOTSHADE_HELPER: tools.helper,
    HOTSPOTSHADE_PRIVILEGED_ENGINE: tools.engine
  };
}

function fakeHelperSpawn(extraEnv = {}) {
  return function (command, args, options) {
    const env = Object.assign({}, options.env, extraEnv);
    return spawn(process.execPath, [fixture, ...args], Object.assign({}, options, { env }));
  };
}

async function waitFor(predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

/* A fake child process whose stdout and exit event the test can order. It
 * needs no real helper, engine, or privilege. */
function fakeHelperChild(pid = 4242) {
  const child = new EventEmitter();
  child.pid = pid;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new Writable({
    write(chunk, encoding, callback) {
      callback();
    }
  });
  child.kill = function () {
    throw new Error('the privileged path must not signal the helper');
  };
  return child;
}

function fakeChildClient(tools, child, extra = {}) {
  return createEngineClient(Object.assign({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    authorizationTimeoutMs: 5000,
    authorizationStopMs: 100,
    helperExitMs: 1000,
    stdoutDrainMs: 1000,
    spawn() {
      return child;
    }
  }, extra));
}

function virtualExecutableFiles() {
  return {
    statSync() {
      return { isFile() { return true; } };
    },
    accessSync() {}
  };
}

test('a development privileged launch accepts explicit path overrides', () => {
  const tools = temporaryTools();
  try {
    const config = resolveEngineConfig({
      argv: ['electron', '.', '--privileged'],
      env: privilegedEnv(tools)
    });
    assert.equal(config.mode, 'engine');
    assert.equal(config.privileged, true);
    assert.equal(config.pkexecPath, tools.pkexec);
    assert.equal(config.helperPath, tools.helper);
    assert.equal(config.enginePath, tools.engine);
    assert.equal(config.executable, '');
    assert.equal(config.demo, false);

    const requested = resolveEngineConfig({ argv: ['electron', '.', '--privileged'], env: privilegedEnv(tools) });
    assert.equal(requested.privileged, true);

    const explicit = resolveEngineConfig({
      argv: ['electron', '.', '--engine', tools.engine],
      env: privilegedEnv(tools)
    });
    assert.equal(explicit.mode, 'engine');
    assert.equal(explicit.privileged, false);
    assert.equal(explicit.executable, tools.engine);

    const demo = resolveEngineConfig({
      argv: ['electron', '.', '--engine-demo'],
      env: privilegedEnv(tools)
    });
    assert.equal(demo.mode, 'engine');
    assert.equal(demo.privileged, false);
    assert.equal(demo.demo, true);
    assert.equal(demo.executable, tools.engine);

    const forcedDemo = resolveEngineConfig({ argv: ['electron', '.', '--demo'], env: privilegedEnv(tools) });
    assert.equal(forcedDemo.mode, 'demo');
  } finally {
    tools.remove();
  }
});

test('a packaged app uses the fixed paths and ignores environment overrides', () => {
  const tools = temporaryTools();
  try {
    const config = resolveEngineConfig({
      argv: [],
      env: Object.assign(privilegedEnv(tools), { HOTSPOTSHADE_ENGINE: tools.engine }),
      isPackaged: true,
      fileSystem: virtualExecutableFiles()
    });
    assert.equal(config.mode, 'engine');
    assert.equal(config.privileged, true);
    assert.equal(config.pkexecPath, DEFAULT_PKEXEC_PATH);
    assert.equal(config.helperPath, DEFAULT_HELPER_PATH);
    assert.equal(config.enginePath, DEFAULT_ENGINE_PATH);
    assert.equal(config.executable, '', 'the packaged engine setting is not a development path');
    assert.equal(config.demo, false);

    const explicit = resolveEngineConfig({
      argv: ['electron', '.', '--engine', tools.engine],
      env: privilegedEnv(tools),
      isPackaged: true
    });
    assert.equal(explicit.mode, 'engine');
    assert.equal(explicit.privileged, false);
    assert.equal(explicit.executable, tools.engine);

    /* A packaged app has no demo mode: the engine demo flag, the engine demo
     * variable, and --demo are ignored. */
    const demo = resolveEngineConfig({
      argv: ['electron', '.', '--engine-demo', '--engine', tools.engine],
      env: Object.assign(privilegedEnv(tools), { HOTSPOTSHADE_ENGINE_DEMO: '1' }),
      isPackaged: true
    });
    assert.equal(demo.mode, 'engine');
    assert.equal(demo.privileged, false);
    assert.equal(demo.demo, false);
    assert.equal(demo.executable, tools.engine);

    for (const argv of [['electron', '.', '--demo'], ['electron', '.', '--engine-demo'], []]) {
      const packaged = resolveEngineConfig({
        argv,
        env: Object.assign(privilegedEnv(tools), { HOTSPOTSHADE_ENGINE_DEMO: 'true' }),
        isPackaged: true,
        fileSystem: virtualExecutableFiles()
      });
      assert.equal(packaged.mode, 'engine', argv.join(' '));
      assert.equal(packaged.demo, false, argv.join(' '));
      assert.equal(packaged.privileged, true, argv.join(' '));
      assert.equal(packaged.enginePath, DEFAULT_ENGINE_PATH);
    }
  } finally {
    tools.remove();
  }
});

test('the privileged defaults and errors are explicit', () => {
  const tools = temporaryTools();
  try {
    const missingHelper = resolveEngineConfig({
      argv: ['electron', '.', '--privileged'],
      env: {
        HOTSPOTSHADE_PRIVILEGED_ENGINE: tools.engine,
        HOTSPOTSHADE_PKEXEC: tools.pkexec,
        HOTSPOTSHADE_HELPER: path.join(tools.directory, 'missing')
      }
    });
    assert.equal(missingHelper.mode, 'error');
    assert.match(missingHelper.error, /privileged helper is missing/);

    const missingEngine = resolveEngineConfig({
      argv: ['electron', '.', '--privileged'],
      env: {
        HOTSPOTSHADE_PRIVILEGED_ENGINE: path.join(tools.directory, 'missing'),
        HOTSPOTSHADE_PKEXEC: tools.pkexec,
        HOTSPOTSHADE_HELPER: tools.helper
      }
    });
    assert.equal(missingEngine.mode, 'error');
    assert.match(missingEngine.error, /packaged engine is missing/);

    const defaults = [DEFAULT_HELPER_PATH, DEFAULT_PKEXEC_PATH, DEFAULT_ENGINE_PATH];
    assert.equal(defaults[0], '/usr/lib/hotspotshade/hotspotshade-helper');
    assert.equal(defaults[1], '/usr/bin/pkexec');
    assert.equal(defaults[2], '/opt/hotspotshade/resources/engine/hotspotshade');
  } finally {
    tools.remove();
  }
});

test('the privileged client sends the secret on stdin and uses one fixed argument', async () => {
  const tools = temporaryTools();
  const calls = [];
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    stopGraceMs: 3000,
    spawn(command, args, options) {
      calls.push({ command, args, env: options.env });
      return spawn(process.execPath, [fixture, ...args], options);
    }
  });
  try {
    const status = await client.call('status');
    assert.equal(status.demo, true);
    assert.equal(status.paired, true);
    assert.equal(client.describe().transport, 'privileged_pkexec');
    assert.equal(client.describe().privileged, true);
    assert.equal(client.isRunning(), true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].command, tools.pkexec);
    assert.deepEqual(calls[0].args, [tools.helper]);
    assert.equal(calls[0].env.HOTSPOTSHADE_ENGINE, undefined);
    const argv = JSON.stringify(calls[0].args);
    const env = JSON.stringify(calls[0].env);
    assert.doesNotMatch(argv, /[0-9a-f]{64}/);
    assert.doesNotMatch(env, /[0-9a-f]{64}/);
    assert.doesNotMatch(argv, /HS1/);
    assert.doesNotMatch(env, /HS1/);

    await client.stop();
    assert.equal(client.isRunning(), false);
    assert.equal(client.describe().connected, false);
    assert.equal(client.exitInfo().code, 0);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a privileged stop waits for the real helper exit and sends no signal', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    /* A direct stop would signal after this budget. The privileged path must
     * ignore it and keep waiting for the helper. */
    stopGraceMs: 50,
    helperExitMs: 3000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_DELAY_MS: '400' })
  });
  try {
    await client.call('status');
    const result = await client.stop();
    assert.deepEqual(result, { stopped: true, timedOut: false });
    assert.equal(client.isRunning(), false);
    assert.equal(client.exitInfo().code, 0, 'the helper exited by itself');
    assert.equal(client.exitInfo().signal, null, 'the app did not signal the helper');
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a helper that outlives the stop budget is reported and blocks a restart', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 100,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_DELAY_MS: '800' })
  });
  try {
    await client.call('status');
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: true,
      failed: true,
      reason: 'helper_exit_timeout'
    });
    assert.ok(client.pid > 0, 'the helper may still be alive');
    assert.equal(client.exitInfo(), null);
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_stop_timeout');
      assert.match(error.message, /still running/);
      return true;
    });
    /* The helper still exits on its own. A new engine must not start before
     * that exit, and the client reports the real exit when it arrives. */
    assert.equal(await waitFor(() => client.exitInfo() !== null, 5000), true);
    assert.equal(client.exitInfo().code, 0);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a slow password prompt does not consume the engine startup budget', async () => {
  const tools = temporaryTools();
  const marker = path.join(tools.directory, 'started');
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    /* The engine budget is short on purpose. The password prompt is slower. */
    startTimeoutMs: 300,
    authorizationTimeoutMs: 4000,
    helperExitMs: 3000,
    spawn: fakeHelperSpawn({
      HS_FAKE_HELPER_AUTHORIZATION_DELAY_MS: '800',
      HS_FAKE_HELPER_STARTED_MARKER: marker
    })
  });
  try {
    const started = Date.now();
    const status = await client.call('status');
    assert.equal(status.demo, true);
    assert.ok(Date.now() - started >= 700, 'the prompt delay was not counted as startup time');
    assert.equal(fs.existsSync(marker), true, 'the fake engine started after authorization');
    const result = await client.stop();
    assert.deepEqual(result, { stopped: true, timedOut: false });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a split port line is not used until its newline arrives', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 3000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_SPLIT_PORT: '1' })
  });
  try {
    const status = await client.call('status');
    assert.equal(status.demo, true);
    assert.deepEqual(await client.stop(), { stopped: true, timedOut: false });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('authorization that finishes after the app stopped waiting starts no engine', async () => {
  const tools = temporaryTools();
  const marker = path.join(tools.directory, 'started');
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 1000,
    authorizationTimeoutMs: 120,
    authorizationStopMs: 2000,
    helperExitMs: 3000,
    spawn: fakeHelperSpawn({
      HS_FAKE_HELPER_AUTHORIZATION_DELAY_MS: '500',
      HS_FAKE_HELPER_STARTED_MARKER: marker
    })
  });
  try {
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_authorization_timeout');
      return true;
    });
    assert.equal(fs.existsSync(marker), false, 'a late helper must not start an engine');
    assert.equal(await waitFor(() => client.exitInfo() !== null, 5000), true);
    assert.equal(client.exitInfo().code, 7, 'the helper reports that it was abandoned');
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a helper that dies on a signal is a failed stop', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 3000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_SIGNAL: 'SIGKILL' })
  });
  try {
    await client.call('status');
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      failed: true,
      reason: 'helper_signaled',
      helperSignal: 'SIGKILL'
    });
    assert.equal(client.exitInfo().signal, 'SIGKILL');
    assert.equal(client.isRunning(), false);
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_stop_incomplete');
      return true;
    });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a helper that reports an engine failure is not a clean stop', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 3000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_CODE: '5' })
  });
  try {
    await client.call('status');
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      failed: true,
      reason: 'engine_failed',
      helperCode: 5
    });
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_stop_incomplete');
      return true;
    });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a helper that reports a cleanup failure is a failed stop with its own reason', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 3000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_CODE: '9' })
  });
  try {
    await client.call('status');
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      failed: true,
      reason: 'engine_cleanup_failed',
      helperCode: 9
    });
    assert.equal(stopFailureKind(result, true), 'cleanup_unconfirmed');
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_stop_incomplete');
      assert.match(error.message, /did not stop cleanly/);
      return true;
    });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a cleanup failure before readiness keeps the start blocked', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_BEFORE_READY: '9' })
  });
  try {
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /could not confirm cleanup/i);
      assert.match(error.message, /inspect the routes/i);
      return true;
    });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a helper setup failure before readiness has a plain message', async () => {
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
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /could not prepare the engine start/i);
      return true;
    });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

async function startFailureMessageFor(env) {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    spawn: fakeHelperSpawn(Object.assign({ HS_FAKE_HELPER_EXIT_BEFORE_READY: '1' }, env))
  });
  try {
    let message = '';
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      message = error.message;
      return true;
    });
    return message;
  } finally {
    await client.dispose();
    tools.remove();
  }
}

test('a helper exit 1 with a known reason line gets that plain message', async () => {
  const message = await startFailureMessageFor({ HS_FAKE_HELPER_REASON: 'HS_REASON engine_unsafe_permissions' });
  assert.match(message, /install directory/i);
  assert.match(message, /unsafe permissions/i);
  assert.match(message, /reinstall/i);
  assert.doesNotMatch(message, /could not prepare the engine start/i);
  assert.doesNotMatch(message, /fake helper/i, 'helper stderr text is never shown');
});

test('a helper exit 1 with no, unknown, or hostile reason keeps the generic message', async () => {
  for (const reason of [
    undefined,
    'HS_REASON not_a_listed_reason',
    'HS_REASON ../../etc/passwd',
    'HS_REASON engine_missing extra text',
    'hs_reason engine_missing',
    'HS_REASON __proto__',
    'HS_REASON constructor'
  ]) {
    const env = reason === undefined ? {} : { HS_FAKE_HELPER_REASON: reason };
    const message = await startFailureMessageFor(env);
    assert.match(message, /could not prepare the engine start/i, String(reason));
  }
});

test('the reason line survives a large stderr flood before it', async () => {
  const message = await startFailureMessageFor({
    HS_FAKE_HELPER_STDERR_FLOOD: '200000',
    HS_FAKE_HELPER_REASON: 'HS_REASON home_unsafe'
  });
  assert.match(message, /not owned by root or is not private/i);
});

test('every helper reason slug has a message and the parser takes the last known line', () => {
  const slugs = Object.keys(HELPER_REASON_MESSAGES);
  assert.ok(slugs.length >= 13);
  for (const slug of slugs) {
    assert.match(slug, /^[a-z_]{1,32}$/);
    assert.equal(helperReasonMessage('HS_REASON ' + slug + '\n'), HELPER_REASON_MESSAGES[slug]);
    assert.ok(HELPER_REASON_MESSAGES[slug].length > 20);
    assert.doesNotMatch(HELPER_REASON_MESSAGES[slug], /secret|token/i);
  }
  assert.equal(
    helperReasonMessage('HS_REASON engine_missing\nnoise\nHS_REASON not_root\r\nhotspotshade-helper: x\n'),
    HELPER_REASON_MESSAGES.not_root
  );
  assert.equal(helperReasonMessage('prefixHS_REASON engine_missing\n'), '');
  assert.equal(helperReasonMessage(''), '');
  assert.equal(helperReasonMessage(undefined), '');
});

test('the reason slugs the app maps are the slugs the helper source can print', () => {
  const source = read('helper/src/main.rs');
  const printed = [...source.matchAll(/^const REASON_[A-Z_]+: &str = "([a-z_]+)";$/gm)].map((match) => match[1]).sort();
  assert.deepEqual(printed, Object.keys(HELPER_REASON_MESSAGES).sort());
});

test('a helper stop timeout is reported before the app stop budget ends', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 5000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_STOP_TIMEOUT_DELAY_MS: '1500' })
  });
  try {
    await client.call('status');
    const started = Date.now();
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: true,
      failed: true,
      reason: 'engine_stop_timeout'
    });
    assert.ok(Date.now() - started < 2000, 'the helper timeout notice returned before the app budget ended');
    assert.ok(client.pid > 0, 'the helper keeps the lock while the engine stops');
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_stop_timeout');
      return true;
    });
    assert.equal(await waitFor(() => client.exitInfo() !== null, 5000), true);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a helper that reports a surviving engine refuses the start', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_BEFORE_READY: '6' })
  });
  try {
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /previous privileged engine is still running/);
      return true;
    });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('an uncertain previous engine state gives recovery guidance', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_BEFORE_READY: '8' })
  });
  try {
    await assert.rejects(client.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /previous engine state could not be verified/);
      assert.match(error.message, /inspect the routes/);
      return true;
    });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('uncertain engine state reaches the desktop IPC status response', async () => {
  const tools = temporaryTools();
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    spawn: fakeHelperSpawn({ HS_FAKE_HELPER_EXIT_BEFORE_READY: '8' })
  });
  const boundary = { call: (operation, params) => client.call(operation, params), describe: () => ({ connected: false }), dispose() {} };
  const router = createRouter({
    backend: createEngineBoundaryBackend(boundary),
    boundary,
    settings: { snapshot: () => ({}) }
  });
  try {
    const result = await router.invoke('status', undefined);
    assert.equal(result.ok, false);
    assert.equal(result.error.code, 'engine_start_failed');
    assert.match(result.error.message, /previous engine state could not be verified/);
    assert.match(result.error.message, /inspect the routes/);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a denied helper becomes one plain authorization error', async () => {
  const tools = temporaryTools();
  const denied = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helperDeny,
    enginePath: tools.engine,
    startTimeoutMs: 2000,
    stopGraceMs: 500,
    spawn(command, args, options) {
      return spawn(process.execPath, [fixture, ...args], options);
    }
  });
  try {
    await assert.rejects(denied.start(), (error) => {
      assert.equal(error.code, 'engine_start_failed');
      assert.match(error.message, /authorization/i);
      return true;
    });
  } finally {
    await denied.dispose();
    tools.remove();
  }
});

const { stopFailureKind } = require('../src/main/lifecycle.js');

/* Wrap the fake helper so the test sees every signal the client sends. The
 * real helper runs as root, so the client must send none. */
function killSpySpawn(extraEnv, signals) {
  const inner = fakeHelperSpawn(extraEnv);
  return function (command, args, options) {
    const real = inner(command, args, options);
    return new Proxy(real, {
      get(target, property) {
        if (property === 'kill') {
          return (signal) => {
            signals.push(signal === undefined ? 'default' : signal);
            return target.kill(signal);
          };
        }
        const value = target[property];
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });
  };
}

for (const code of [126, 127, 7]) {
  test('a helper that exits ' + code + ' before it is ready started no engine', async () => {
    const tools = temporaryTools();
    const signals = [];
    const client = createEngineClient({
      privileged: true,
      pkexecPath: tools.pkexec,
      helperPath: tools.helper,
      enginePath: tools.engine,
      startTimeoutMs: 2000,
      spawn: killSpySpawn({ HS_FAKE_HELPER_EXIT_BEFORE_READY: String(code) }, signals)
    });
    try {
      await assert.rejects(client.start(), { code: 'engine_start_failed' });
      const result = await client.dispose();
      assert.equal(result.stopped, true);
      assert.equal(result.timedOut, false);
      assert.equal(result.neverStarted, true);
      assert.equal(result.helperCode, code);
      assert.equal(Object.hasOwn(result, 'failed'), false);
      assert.equal(Object.hasOwn(result, 'cleanupUnconfirmed'), false);
      assert.equal(stopFailureKind(result, true), '', 'the quit path shows no warning');
      /* Asking again returns the same stop result. */
      assert.equal(await client.stop(), result);
      assert.deepEqual(signals, [], 'the privileged path sends no signal');
    } finally {
      tools.remove();
    }
  });
}

test('a helper that exits 126 after it was ready is still a failed stop', async () => {
  const tools = temporaryTools();
  const signals = [];
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 3000,
    spawn: killSpySpawn({ HS_FAKE_HELPER_EXIT_CODE: '126' }, signals)
  });
  try {
    await client.call('status');
    const result = await client.stop();
    assert.deepEqual(result, {
      stopped: false,
      timedOut: false,
      failed: true,
      reason: 'helper_failed',
      helperCode: 126
    });
    assert.equal(stopFailureKind(result, true), 'stop_failed');
    assert.deepEqual(signals, []);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a prompt that is still open at quit is reported as unconfirmed, not as no engine', async () => {
  const tools = temporaryTools();
  const signals = [];
  const marker = path.join(tools.directory, 'engine-started');
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 1000,
    authorizationTimeoutMs: 5000,
    authorizationStopMs: 150,
    helperExitMs: 3000,
    spawn: killSpySpawn({
      HS_FAKE_HELPER_AUTHORIZATION_DELAY_MS: '1500',
      HS_FAKE_HELPER_STARTED_MARKER: marker
    }, signals)
  });
  try {
    const starting = client.start().catch((error) => error);
    await new Promise((resolve) => setTimeout(resolve, 200));
    const result = await client.stop();
    await starting;
    assert.equal(result.stopped, false);
    assert.equal(result.timedOut, true);
    assert.equal(result.reason, 'authorization_unconfirmed');
    assert.equal(stopFailureKind(result, true), 'authorization_unconfirmed');
    assert.equal(Object.hasOwn(result, 'neverStarted'), false);
    assert.deepEqual(signals, [], 'the privileged path sends no signal');
    assert.equal(await waitFor(() => client.exitInfo() !== null, 5000), true);
    assert.equal(client.exitInfo().code, 7);
    assert.equal(fs.existsSync(marker), false, 'a late helper must not start an engine');
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a privileged stop that times out sends no signal', async () => {
  const tools = temporaryTools();
  const signals = [];
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 5000,
    helperExitMs: 300,
    spawn: killSpySpawn({ HS_FAKE_HELPER_EXIT_DELAY_MS: '2000' }, signals)
  });
  try {
    await client.call('status');
    const result = await client.stop();
    assert.equal(result.stopped, false);
    assert.equal(result.timedOut, true);
    assert.equal(result.reason, 'helper_exit_timeout');
    assert.equal(Object.hasOwn(result, 'cleanupUnconfirmed'), false);
    assert.equal(Object.hasOwn(result, 'stillRunning'), false);
    assert.equal(stopFailureKind(result, true), 'stop_timeout');
    assert.deepEqual(signals, [], 'the app never signals the root helper');
  } finally {
    assert.equal(await waitFor(() => client.exitInfo() !== null, 5000), true);
    await client.dispose();
    tools.remove();
  }
});

test('a helper that prints HS_READY and then exits 7 started no engine', async () => {
  const tools = temporaryTools();
  const helper = path.join(tools.directory, 'ready-then-abandon.js');
  fs.writeFileSync(helper, "process.stdout.write('HS_READY\\n');\nsetTimeout(function () { process.exit(7); }, 100);\n");
  const client = createEngineClient({
    privileged: true,
    pkexecPath: tools.pkexec,
    helperPath: tools.helper,
    enginePath: tools.engine,
    startTimeoutMs: 3000,
    spawn(command, args, options) {
      return spawn(process.execPath, [helper], options);
    }
  });
  try {
    await assert.rejects(client.start(), { code: 'engine_start_failed' });
    const result = await client.dispose();
    assert.equal(result.stopped, true);
    assert.equal(result.neverStarted, true);
    assert.equal(result.helperCode, 7);
    assert.equal(stopFailureKind(result, true), '');
  } finally {
    tools.remove();
  }
});

test('a helper exit before its buffered port line is not treated as no engine', async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child);
  try {
    const starting = client.start().catch((error) => error);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const stopping = client.stop();
    /* The exit event is delivered before the buffered readiness lines. A
     * client that classifies on the exit event alone would wrongly claim that
     * no engine started. */
    child.emit('exit', 7, null);
    child.stdout.write('HS_READY\nHS_PORT 49152\n');
    child.stdout.end();
    const result = await stopping;
    const error = await starting;
    assert.equal(Object.hasOwn(result, 'neverStarted'), false);
    assert.equal(result.stopped, false);
    assert.equal(result.failed, true);
    assert.equal(result.reason, 'helper_abandoned_after_start');
    assert.equal(result.helperCode, 7);
    assert.equal(stopFailureKind(result, true), 'stop_failed');
    assert.equal(error.code, 'engine_start_failed');
    assert.match(error.message, /after the engine start/);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

for (const exitCode of [7, 127]) test(`helper exit ${exitCode} with unclosed stdout reports readiness uncertainty`, async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child, {
    authorizationStopMs: 2000,
    stdoutDrainMs: 100
  });
  try {
    const starting = client.start().catch((error) => error);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const stopping = client.stop();
    child.emit('exit', exitCode, null);
    const result = await stopping;
    const error = await starting;
    assert.equal(Object.hasOwn(result, 'neverStarted'), false);
    assert.equal(result.stopped, false);
    assert.equal(result.failed, true);
    assert.equal(result.reason, 'helper_readiness_unconfirmed');
    assert.equal(stopFailureKind(result, true), 'stop_failed');
    assert.equal(error.code, 'engine_start_failed');
    assert.match(error.message, /could confirm whether it started an engine/);
  } finally {
    child.stdout.end();
    await client.dispose();
    tools.remove();
  }
});

test('a helper that exits zero after readiness but before a port is not a clean stop', async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child);
  try {
    const starting = client.start().catch((error) => error);
    await new Promise((resolve) => setTimeout(resolve, 50));
    child.stdout.write('HS_READY\n');
    child.emit('exit', 0, null);
    child.stdout.end();
    const error = await starting;
    const result = await client.dispose();
    assert.equal(result.stopped, false);
    assert.equal(result.timedOut, false);
    assert.equal(result.failed, true);
    assert.equal(result.reason, 'helper_exit_before_port');
    assert.equal(stopFailureKind(result, true), 'stop_failed');
    assert.equal(Object.hasOwn(result, 'neverStarted'), false);
    assert.equal(error.code, 'engine_start_failed');
    assert.match(error.message, /engine stopped during startup|started an engine/i);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('HS_READY during the authorization stop wait moves to the helper budget', async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child, {
    authorizationTimeoutMs: 5000,
    authorizationStopMs: 150,
    helperExitMs: 2000,
    stdoutDrainMs: 1000
  });
  try {
    const starting = client.start().catch((error) => error);
    const stopping = client.stop();
    /* The real readiness line arrives late in the short authorization wait,
     * after the stop began. The helper then needs the longer supervised-helper
     * budget to stop its engine and exit. */
    setTimeout(function () { child.stdout.write('HS_READY\n'); }, 100);
    setTimeout(function () { child.stdout.write('HS_PORT 49152\n'); }, 120);
    setTimeout(function () {
      child.stdout.end();
      child.emit('exit', 0, null);
    }, 350);

    const [startError, result] = await Promise.all([starting, stopping]);
    assert.equal(startError.code, 'engine_stopped', 'the racing start never returns a client');
    assert.deepEqual(result, { stopped: true, timedOut: false });
    assert.equal(client.exitInfo().code, 0);
    assert.equal(client.describe().connected, false);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('readiness queued at the authorization deadline gets the helper budget', async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child, { authorizationStopMs: 0, helperExitMs: 1000 });
  try {
    const starting = client.start().catch((error) => error);
    setImmediate(() => { child.stdout.write('HS_READY\nHS_PORT 49152\n'); });
    const stopping = client.stop();
    setTimeout(() => { child.stdout.end(); child.emit('exit', 0, null); }, 50);
    const [startError, result] = await Promise.all([starting, stopping]);
    assert.equal(startError.code, 'engine_stopped');
    assert.deepEqual(result, { stopped: true, timedOut: false });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a call resumed after stop does not use the captured client', async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child);
  try {
    const starting = client.start();
    child.stdout.write('HS_READY\nHS_PORT 49152\n');
    await starting;
    const request = client.call('status');
    const stopping = client.stop();
    child.stdout.end();
    child.emit('exit', 0, null);
    await assert.rejects(request, { code: 'engine_stopped' });
    assert.deepEqual(await stopping, { stopped: true, timedOut: false });
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a port line before the stop budget ends never revives the stopped start', async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child, {
    authorizationTimeoutMs: 5000,
    authorizationStopMs: 100,
    helperExitMs: 500,
    stdoutDrainMs: 1000
  });
  try {
    const starting = client.start().catch((error) => error);
    const startedAt = Date.now();
    const stopping = client.stop();
    setTimeout(function () { child.stdout.write('HS_READY\n'); }, 30);
    setTimeout(function () { child.stdout.write('HS_PORT 49152\n'); }, 60);

    const [startError, result] = await Promise.all([starting, stopping]);
    const elapsed = Date.now() - startedAt;
    assert.equal(startError.code, 'engine_stopped', 'the racing start never returns a client');
    assert.equal(result.stopped, false);
    assert.equal(result.timedOut, true);
    assert.equal(result.reason, 'helper_exit_timeout');
    assert.ok(elapsed >= 400, 'the stop used the helper budget, not only the authorization wait');
    assert.ok(client.pid > 0, 'the helper may still be alive');
    assert.equal(client.exitInfo(), null);
    assert.equal(client.describe().connected, false);
  } finally {
    await client.dispose();
    tools.remove();
  }
});

test('a port line after the stop timeout never reads the cleared secret', async () => {
  const tools = temporaryTools();
  const child = fakeHelperChild();
  const client = fakeChildClient(tools, child, {
    authorizationTimeoutMs: 5000,
    authorizationStopMs: 80,
    helperExitMs: 300,
    stdoutDrainMs: 1000
  });
  try {
    const starting = client.start().catch((error) => error);
    const stopping = client.stop();
    const result = await stopping;
    assert.equal(result.stopped, false);
    assert.equal(result.timedOut, true);
    assert.equal(result.reason, 'authorization_unconfirmed');
    assert.equal(Object.hasOwn(result, 'neverStarted'), false);

    const startError = await starting;
    assert.equal(startError.code, 'engine_stopped');
    /* The stop has already cleared the secret and the client. A late
     * readiness and port line must not create a new client or throw a
     * secret-validation error. */
    child.stdout.write('HS_READY\nHS_PORT 49152\n');
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(client.exitInfo(), null, 'no exit was observed');
    assert.ok(client.pid > 0, 'the helper may still be alive');
    assert.equal(client.describe().connected, false);
    await assert.rejects(client.start(), { code: 'engine_stop_timeout' });
  } finally {
    await client.dispose();
    tools.remove();
  }
});
