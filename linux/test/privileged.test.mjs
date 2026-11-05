import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  createEngineClient,
  resolveEngineConfig
} = require('../src/backend/engine-client.js');
const {
  DEFAULT_ENGINE_PATH,
  DEFAULT_HELPER_PATH,
  DEFAULT_PKEXEC_PATH
} = require('../src/backend/engine-client.js');

const here = path.dirname(fileURLToPath(import.meta.url));
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

test('a packaged app selects the fixed privileged helper', () => {
  const tools = temporaryTools();
  try {
    const config = resolveEngineConfig({
      argv: [],
      env: privilegedEnv(tools),
      isPackaged: true
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
      env: privilegedEnv(tools),
      isPackaged: true
    });
    assert.equal(explicit.mode, 'engine');
    assert.equal(explicit.privileged, false);
    assert.equal(explicit.executable, tools.engine);

    const demo = resolveEngineConfig({
      argv: ['electron', '.', '--engine-demo'],
      env: privilegedEnv(tools),
      isPackaged: true
    });
    assert.equal(demo.mode, 'engine');
    assert.equal(demo.privileged, false);
    assert.equal(demo.demo, true);
    assert.equal(demo.executable, tools.engine);

    const forcedDemo = resolveEngineConfig({ argv: ['electron', '.', '--demo'], env: privilegedEnv(tools), isPackaged: true });
    assert.equal(forcedDemo.mode, 'demo');
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
