import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const script = path.join(root, 'scripts', 'test-container.sh');

function withFixture(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-container-test-'));
  try {
    const docker = path.join(directory, 'docker');
    const log = path.join(directory, 'docker.log');
    fs.writeFileSync(docker, '#!/bin/sh\nprintf "%s\\n" CALL "$@" >> "$TEST_DOCKER_LOG"\n');
    fs.chmodSync(docker, 0o755);
    const engine = path.join(directory, 'engine');
    fs.writeFileSync(engine, '#!/bin/sh\nexit 0\n');
    fs.chmodSync(engine, 0o755);
    const env = {
      ...process.env,
      PATH: `${directory}:${process.env.PATH}`,
      TEST_DOCKER_LOG: log,
      HS_TEST_USE_EXISTING_IMAGE: '1',
      HOTSPOTSHADE_BIN: engine,
    };
    run({ directory, engine, env, log });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function invoke(env, mode = 'main-engine-warning') {
  return spawnSync('sh', [script, mode], { env, encoding: 'utf8', timeout: 5000 });
}

test('warning container validates the engine before invoking Docker', () => {
  withFixture(({ directory, env, log }) => {
    const nonExecutable = path.join(directory, 'not-executable');
    fs.writeFileSync(nonExecutable, 'not an executable');
    for (const value of ['', 'relative/engine', path.join(directory, 'missing'), nonExecutable]) {
      const result = invoke({ ...env, HOTSPOTSHADE_BIN: value });
      assert.equal(result.status, 2, result.stderr);
      assert.match(result.stderr, /HOTSPOTSHADE_BIN/);
      assert.equal(fs.existsSync(log), false);
    }
    const result = invoke(env, 'unknown');
    assert.equal(result.status, 2, result.stderr);
    assert.equal(fs.existsSync(log), false);
  });
});

test('warning container passes the restricted demo configuration to Docker', () => {
  withFixture(({ engine, env, log }) => {
    const result = invoke(env);
    assert.equal(result.status, 0, result.stderr);
    const calls = fs.readFileSync(log, 'utf8').trim().split('\nCALL\n');
    assert.deepEqual(calls[0].split('\n'), ['CALL', 'image', 'inspect', 'hotspotshade-linux-test:45.2.3']);
    const args = calls[1].split('\n');
    assert.equal(args[0], 'run');
    for (const [option, value] of [['--network', 'none'], ['--cap-drop', 'ALL']]) {
      assert.notEqual(args.indexOf(option), -1);
      assert.equal(args[args.indexOf(option) + 1], value);
    }
    for (const value of [
      '--rm', '--init', `${root}:/work:ro`, `${engine}:/engine/hotspotshade:ro`,
      'HOTSPOTSHADE_ENGINE=/engine/hotspotshade', 'HOTSPOTSHADE_ENGINE_DEMO=1',
      'HS_TEST_DEMO_CRASH_WARNING=1',
    ]) assert.ok(args.includes(value), `missing ${value}`);
    assert.ok(args.some((arg) => arg.includes('electron test/main-engine-launch.js')));
  });
});

test('real engine window uses an offline, read-only container without demo mode', () => {
  withFixture(({ engine, env, log }) => {
    const result = invoke(env, 'real-engine-window');
    assert.equal(result.status, 0, result.stderr);
    const calls = fs.readFileSync(log, 'utf8').trim().split('\nCALL\n');
    const args = calls[1].split('\n');
    assert.ok(args.includes('--read-only'));
    assert.equal(args[args.indexOf('--network') + 1], 'none');
    assert.ok(args.includes(`${root}:/work:ro`));
    assert.ok(args.includes(`${engine}:/engine/hotspotshade:ro`));
    assert.ok(args.includes('HS_REAL_ENGINE_BIN=/engine/hotspotshade'));
    assert.ok(args.includes('HS_TEST_NETWORK_CONFINED=1'));
    assert.equal(args.includes('HOTSPOTSHADE_ENGINE_DEMO=1'), false);
    assert.ok(args.includes('/work/test/real-engine-window-main.js'));
  });
});
