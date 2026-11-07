import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

/* Real-engine backend test (L2).
 *
 * This drives the real createEngineClient, createEngineBackend, and IPC router
 * against the REAL HotspotShade engine binary named by HOTSPOTSHADE_BIN. The
 * engine runs as the signed-in user in non-demo mode with a temporary HOME.
 *
 * It is hermetic on purpose. It calls only operations that cannot reach the
 * network: status, pair state, failures, diagnostics, activity, a start that is
 * refused before any socket is opened, and stop. It never calls pair, forget,
 * or probe, because those contact the default gateway on port 18090 in non-demo
 * mode. A phone start while unpaired returns "pair first" before any network
 * work. A direct start by a non-root user is refused at the privilege check
 * before any TUN device or route work. The test compares the interface list and
 * the routing table before and after and fails if either changed.
 *
 * It skips when HOTSPOTSHADE_BIN is not set, and when run as root, because a
 * root engine would pass the privilege check and could start a real tunnel.
 *
 * It does not prove a tunnel, a real polkit prompt, the real Rust helper, or a
 * live hotspot. The privileged-client case uses a clearly labeled JavaScript
 * stand-in for the helper (fixtures/real-engine-helper-standin.js).
 */

const require = createRequire(import.meta.url);
const { createEngineClient } = require('../src/backend/engine-client.js');
const { createEngineBackend } = require('../src/backend/engine-backend.js');
const { createSessionBackend } = require('../src/backend/session-backend.js');
const { createRouter } = require('../src/main/ipc.js');
const { stopFailureKind } = require('../src/main/lifecycle.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const standin = path.join(here, 'fixtures', 'real-engine-helper-standin.js');
const parentScript = path.join(here, 'fixtures', 'real-engine-parent.js');
const binary = process.env.HOTSPOTSHADE_BIN || '';
const isRoot = typeof process.geteuid === 'function' && process.geteuid() === 0;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function skipReason() {
  if (!binary) return 'Set HOTSPOTSHADE_BIN to the built engine to run the real-engine backend test.';
  if (!path.isAbsolute(binary)) return 'HOTSPOTSHADE_BIN must be an absolute path.';
  try { fs.accessSync(binary, fs.constants.X_OK); } catch (error) { return 'HOTSPOTSHADE_BIN is not executable.'; }
  if (isRoot) return 'Skipped as root: a root engine could start a real tunnel.';
  return false;
}
const skip = skipReason();

/* ---- host network snapshot (read only) ---- */

function interfaceSnapshot() {
  const names = Object.entries(os.networkInterfaces()).map(([name, list]) => (
    name + ' ' + (list || []).filter((entry) => entry.family === 'IPv4').map((entry) => entry.address).sort().join(',')
  ));
  return names.sort();
}

function routeSnapshot() {
  if (process.platform === 'linux') {
    const read = (file) => {
      try { return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).sort(); } catch (error) { return []; }
    };
    return read('/proc/net/route').concat(read('/proc/net/ipv6_route'));
  }
  if (process.platform === 'darwin') {
    // Drop neighbor-cache rows (flags W or L) and the Expire column; those
    // change with ordinary traffic and are not routes that the engine owns.
    const text = execFileSync('/usr/sbin/netstat', ['-rn'], { encoding: 'utf8' });
    return text.split('\n').map((line) => line.trim().split(/\s+/)).filter((cells) => {
      if (cells.length < 4) return false;
      const flags = cells[2];
      return /^[A-Za-z0-9]+$/.test(flags) && !/[WL]/.test(flags) && cells[0] !== 'Destination';
    }).map((cells) => cells.slice(0, 4).join(' ')).sort();
  }
  return [];
}

function networkSnapshot() {
  return { interfaces: interfaceSnapshot(), routes: routeSnapshot() };
}

/* ---- sandbox ---- */

function makeSandbox() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-real-backend-'));
  fs.chmodSync(home, 0o700);
  // The client only checks that these paths are executable files. The stand-in
  // test never runs them; the spawn hook below runs the JavaScript stand-in.
  const pkexec = path.join(home, 'pkexec');
  const helper = path.join(home, 'hotspotshade-helper');
  fs.writeFileSync(pkexec, '#!/bin/sh\nexit 99\n', { mode: 0o755 });
  fs.writeFileSync(helper, '#!/bin/sh\nexit 99\n', { mode: 0o755 });
  return {
    home,
    pkexec,
    helper,
    pidFile: path.join(home, 'engine.pid'),
    remove() { fs.rmSync(home, { recursive: true, force: true }); }
  };
}

function directClient(sandbox, spawned) {
  return createEngineClient({
    executable: binary,
    stopGraceMs: 6000,
    spawn(command, args, options) {
      const child = spawn(command, args, Object.assign({}, options, {
        env: Object.assign({}, options.env, { HOME: sandbox.home })
      }));
      if (spawned) spawned.push({ command, args, child });
      return child;
    }
  });
}

function standinClient(sandbox, spawned) {
  return createEngineClient({
    privileged: true,
    pkexecPath: sandbox.pkexec,
    helperPath: sandbox.helper,
    enginePath: binary,
    helperExitMs: 20000,
    spawn(command, args, options) {
      const child = spawn(process.execPath, [standin], Object.assign({}, options, {
        env: Object.assign({}, options.env, {
          HS_STANDIN_ENGINE: binary,
          HS_STANDIN_HOME: sandbox.home,
          HS_STANDIN_PID_FILE: sandbox.pidFile
        })
      }));
      if (spawned) spawned.push({ command, args, child });
      return child;
    }
  });
}

function routerFor(backend, client) {
  return createRouter({
    backend,
    boundary: { describe: () => client.describe() },
    settings: { snapshot: () => ({}) }
  });
}

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}

async function gone(pid, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!alive(pid)) return true;
    await delay(50);
  }
  return false;
}

function rawGet(port, pathName, authorization) {
  return new Promise((resolve, reject) => {
    const headers = authorization ? { Authorization: authorization } : {};
    const request = http.request({ host: '127.0.0.1', port, path: pathName, method: 'GET', headers }, (response) => {
      response.resume();
      response.on('end', () => resolve(response.statusCode));
    });
    request.on('error', reject);
    request.setTimeout(3000, () => request.destroy(new Error('timeout')));
    request.end();
  });
}

function commandLine(pid) {
  return execFileSync('ps', ['-o', 'command=', '-p', String(pid)], { encoding: 'utf8' }).trim();
}

function assertNoSecretInProcess(pid) {
  const command = commandLine(pid);
  assert.doesNotMatch(command, /[0-9a-f]{64}/i, 'no 64-digit hex secret on the engine command line');
  assert.match(command, /--token-fd 3/);
  assert.match(command, /--parent-fd 4/);
  assert.doesNotMatch(command, /--demo/);
  if (process.platform === 'linux') {
    const environment = fs.readFileSync('/proc/' + pid + '/environ', 'utf8');
    assert.doesNotMatch(environment, /[0-9a-f]{64}/i, 'no secret in the engine environment');
  }
}

/* The read-only and refused operations that both transports must answer the
 * same way. `backend` is the real engine backend; `router` is the real router. */
async function exerciseBackend(t, backend, router, port, secretless) {
  const status = await backend.status();
  assert.equal(status.demo, false, 'the engine is not in demo mode');
  assert.equal(status.api, 1);
  assert.equal(status.running, false);
  assert.equal(status.paired, false);
  assert.equal(status.cleanup_blocked, false);
  assert.equal(status.mode, null);
  assert.equal(status.platform.os, process.platform === 'darwin' ? 'macos' : process.platform);
  assert.equal(status.platform.admin, false, 'the engine runs without administrator rights');
  assert.equal(status.last_stop.reason, null);

  const pair = await backend.pairState();
  assert.equal(pair.state, 'idle');
  assert.equal(pair.code, null);
  assert.equal(pair.error, null);

  const failures = await backend.failures();
  assert.equal(failures.ok, true);
  assert.equal(failures.total, 0);
  assert.deepEqual(failures.recent, []);

  const diagnostics = await backend.diagnostics();
  assert.equal(diagnostics.ok, true);
  assert.equal(diagnostics.running, false);
  assert.equal(diagnostics.engine.version, '0.1.0');

  const activity = await backend.activity({ since: 0 });
  assert.deepEqual(activity.logs, []);
  assert.equal(activity.next, 0);

  // A phone start while unpaired is refused before any network work.
  await assert.rejects(backend.start({ mode: 'phone', ping: false }), (error) => {
    assert.equal(error.name, 'BackendError');
    assert.match(error.message, /Pair with the source device first/);
    return true;
  });
  // A direct start by a non-root user is refused at the privilege check.
  await assert.rejects(backend.start({ mode: 'direct' }), (error) => {
    assert.equal(error.code, 'admin_required');
    assert.match(error.message, /Administrator/);
    return true;
  });
  // The same refusals through the IPC router keep the error code and message.
  const viaRouter = await router.invoke('start', { mode: 'direct', ping: false });
  assert.equal(viaRouter.ok, false);
  assert.equal(viaRouter.error.code, 'admin_required');
  const phoneViaRouter = await router.invoke('start', { mode: 'phone', ping: true });
  assert.equal(phoneViaRouter.ok, false);
  assert.match(phoneViaRouter.error.message, /Pair with the source device first/);
  const bootstrap = await router.invoke('bootstrap', undefined);
  assert.equal(bootstrap.ok, true);
  assert.equal(bootstrap.data.mode, 'engine');
  assert.equal(bootstrap.data.demo, false);

  // A refused start must not change anything the engine reports.
  const after = await backend.status();
  assert.equal(after.running, false);
  assert.equal(after.mode, null);
  assert.equal(after.cleanup_blocked, false);
  assert.equal(after.last_stop.reason, null);

  // Stop with nothing running is harmless and idempotent.
  const stopped = await backend.stop();
  assert.equal(stopped.running, false);
  assert.equal((await backend.status()).running, false);

  // A demo-only call is refused by the engine backend itself.
  assert.throws(() => backend.applyScenario({ name: 'x' }), (error) => error.code === 'demo_only');

  // Authentication: the engine rejects a request with no or a wrong bearer.
  if (!secretless) {
    assert.equal(await rawGet(port, '/api/status'), 401);
    assert.equal(await rawGet(port, '/api/status', 'Bearer ' + 'cd'.repeat(32)), 401);
  }
  void t;
}

test('the direct client and backend work against a real non-demo engine without touching the network', { skip, timeout: 60000 }, async (t) => {
  const sandbox = makeSandbox();
  const before = networkSnapshot();
  const spawned = [];
  const client = directClient(sandbox, spawned);
  const backend = createEngineBackend({ client });
  try {
    const http_ = await client.start();
    assert.equal(spawned.length, 1);
    assert.deepEqual(spawned[0].args, [
      'gui', '--no-open', '--port', '0', '--port-file', spawned[0].args[5],
      '--token-fd', '3', '--parent-fd', '4'
    ]);
    // The liveness channel and the secret channel are descriptors 3 and 4.
    assert.ok(spawned[0].child.stdio[3] && spawned[0].child.stdio[4]);
    assert.equal(client.describe().transport, 'loopback_http');
    assert.equal(client.describe().tunnel, 'engine_service');
    assert.equal(client.describe().connected, true);
    assert.equal(fs.statSync(client.tempDirectory).mode & 0o777, 0o700);
    const pid = client.pid;
    assertNoSecretInProcess(pid);
    await exerciseBackend(t, backend, routerFor(backend, client), http_.port, false);
    assert.equal(alive(pid), true);

    const directory = client.tempDirectory;
    const result = await backend.dispose();
    assert.deepEqual(result, { stopped: true, timedOut: false });
    assert.equal(stopFailureKind(result, true), '');
    assert.equal(await gone(pid), true, 'the engine exited after dispose');
    assert.equal(client.exitInfo().code, 0);
    assert.equal(fs.existsSync(directory), false, 'the private port directory is removed');
    assert.equal(backend.describeEngine().connected, false);
    await assert.rejects(backend.status(), (error) => error.code === 'engine_stopped' || /stopping|stopped/i.test(error.message));
  } finally {
    await client.dispose();
    sandbox.remove();
  }
  assert.deepEqual(networkSnapshot(), before, 'the interface list and routes did not change');
});

test('the pkexec client path works against a real engine through the labeled JavaScript helper stand-in', { skip, timeout: 60000 }, async (t) => {
  const sandbox = makeSandbox();
  const before = networkSnapshot();
  const spawned = [];
  const client = standinClient(sandbox, spawned);
  const backend = createEngineBackend({ client });
  try {
    const http_ = await client.start();
    // The client calls pkexec with the helper path and nothing else.
    assert.equal(spawned[0].command, sandbox.pkexec);
    assert.deepEqual(spawned[0].args, [sandbox.helper]);
    assert.equal(client.describe().transport, 'privileged_pkexec');
    const enginePid = Number(fs.readFileSync(sandbox.pidFile, 'utf8'));
    assert.ok(enginePid > 1 && alive(enginePid));
    assertNoSecretInProcess(enginePid);
    await exerciseBackend(t, backend, routerFor(backend, client), http_.port, false);

    const result = await backend.dispose();
    assert.equal(result.stopped, true);
    assert.equal(result.timedOut, false);
    assert.equal(result.failed, undefined);
    assert.equal(stopFailureKind(result, true), '');
    assert.equal(await gone(enginePid), true, 'closing the request pipe stopped the real engine');
    assert.equal(client.exitInfo().code, 0, 'the stand-in reported a clean engine stop');
  } finally {
    await client.dispose();
    sandbox.remove();
  }
  assert.deepEqual(networkSnapshot(), before, 'the interface list and routes did not change');
});

test('the client reports engine loss when the real engine loses its liveness channel', { skip, timeout: 60000 }, async () => {
  const sandbox = makeSandbox();
  const spawned = [];
  const client = directClient(sandbox, spawned);
  try {
    await client.start();
    const pid = client.pid;
    // Destroy the parent end completely; a half close is not parent loss.
    spawned[0].child.stdio[4].destroy();
    assert.equal(await gone(pid), true, 'the engine exited when descriptor 4 closed');
    await delay(100);
    assert.equal(client.describe().connected, false);
    await assert.rejects(client.call('status'), (error) => {
      assert.equal(error.code, 'engine_stopped');
      assert.match(error.message, /stopped unexpectedly/);
      return true;
    });
    assert.equal(client.exitInfo().code, 0);
  } finally {
    await client.dispose();
    sandbox.remove();
  }
});

for (const mode of ['direct', 'standin']) {
  test('the real engine stops by itself when the app process is killed (' + mode + ')', { skip, timeout: 60000 }, async () => {
    const sandbox = makeSandbox();
    const before = networkSnapshot();
    let parent = null;
    let enginePid = 0;
    let directory = '';
    try {
      parent = spawn(process.execPath, [parentScript], {
        env: {
          PATH: process.env.PATH,
          HOTSPOTSHADE_BIN: binary,
          HS_PARENT_HOME: sandbox.home,
          HS_PARENT_MODE: mode,
          HS_PARENT_PKEXEC: sandbox.pkexec,
          HS_PARENT_HELPER: sandbox.helper,
          HS_STANDIN_PID_FILE: sandbox.pidFile
        },
        stdio: ['ignore', 'pipe', 'pipe']
      });
      let stderr = '';
      parent.stderr.on('data', (chunk) => { stderr += chunk; });
      const line = await new Promise((resolve, reject) => {
        let text = '';
        const timer = setTimeout(() => reject(new Error('the parent did not report readiness')), 20000);
        parent.stdout.on('data', (chunk) => {
          text += chunk;
          const index = text.indexOf('\n');
          if (index !== -1) { clearTimeout(timer); resolve(text.slice(0, index)); }
        });
        parent.once('exit', () => { clearTimeout(timer); reject(new Error('the parent exited early: ' + stderr)); });
      });
      const info = JSON.parse(line);
      directory = info.tempDirectory || '';
      enginePid = mode === 'standin' ? Number(fs.readFileSync(sandbox.pidFile, 'utf8')) : info.pid;
      assert.ok(enginePid > 1 && alive(enginePid), 'the engine is running before the kill');
      parent.kill('SIGKILL');
      assert.equal(await gone(enginePid, 15000), true, 'the engine exited after its parent was killed');
    } finally {
      if (parent && parent.exitCode === null) parent.kill('SIGKILL');
      if (enginePid > 1 && alive(enginePid)) process.kill(enginePid, 'SIGTERM');
      if (directory) fs.rmSync(directory, { recursive: true, force: true });
      sandbox.remove();
    }
    assert.deepEqual(networkSnapshot(), before, 'the interface list and routes did not change');
  });
}

/* Invariant 14 with the real engine: the packaged session runs only the
 * unprivileged user engine at open. pkexec (here the labeled stand-in) runs
 * only for a tunnel start, and a confirmed stop returns to the user engine. */
test('opening the packaged session starts only an unprivileged engine and calls pkexec only at a tunnel start', { skip, timeout: 90000 }, async () => {
  const sandbox = makeSandbox();
  const before = networkSnapshot();
  const dataHome = path.join(sandbox.home, 'data', 'hotspotshade', 'engine');
  const userSpawns = [];
  const pkexecSpawns = [];
  const userClient = createEngineClient({
    executable: binary,
    handoff: true,
    home: dataHome,
    stopGraceMs: 6000,
    spawn(command, args, options) {
      const child = spawn(command, args, options);
      userSpawns.push({ command, args, options, child });
      return child;
    }
  });
  const backend = createSessionBackend({
    userClient,
    createRootClient(handoffStream) {
      return createEngineClient({
        privileged: true,
        pkexecPath: sandbox.pkexec,
        helperPath: sandbox.helper,
        enginePath: binary,
        handoffStream,
        helperExitMs: 20000,
        spawn(command, args, options) {
          pkexecSpawns.push({ command, args, stdio: options.stdio });
          return spawn(process.execPath, [standin], Object.assign({}, options, {
            env: Object.assign({}, options.env, {
              HS_STANDIN_ENGINE: binary,
              HS_STANDIN_HOME: sandbox.home,
              HS_STANDIN_PID_FILE: sandbox.pidFile
            })
          }));
        }
      });
    }
  });
  try {
    await userClient.start();
    assert.equal(userSpawns.length, 1);
    assert.equal(userSpawns[0].command, binary, 'the app runs the engine itself, not pkexec');
    assert.deepEqual(userSpawns[0].args.slice(-2), ['--handoff-fd', '0']);
    assert.equal(userSpawns[0].options.env.HOME, dataHome);
    assertNoSecretInProcess(userClient.pid);

    // Dashboard, pairing state, Settings data, Activity, diagnostics, and
    // failures all work with no administrator authorization.
    const status = await backend.status();
    assert.equal(status.platform.admin, false, 'the user engine runs without administrator rights');
    assert.equal(status.running, false);
    assert.equal(status.paired, false);
    assert.equal((await backend.pairState()).state, 'idle');
    assert.equal((await backend.failures()).ok, true);
    assert.equal((await backend.diagnostics()).ok, true);
    assert.deepEqual((await backend.activity({ since: 0 })).logs, []);
    assert.equal(backend.describeEngine().privileged, false);
    assert.equal(pkexecSpawns.length, 0, 'opening and reading status never calls pkexec');

    // The user engine created its identity key in the user data directory.
    const key = path.join(dataHome, 'Library', 'Application Support', 'hotspotshade', 'identity.key');
    assert.equal(fs.statSync(key).mode & 0o777, 0o600);

    // A phone start while unpaired is refused by the user engine before pkexec.
    await assert.rejects(backend.start({ mode: 'phone', ping: true }), (error) => {
      // Both the macOS and the Linux engine builds answer an unpaired handoff
      // request with not_paired.
      assert.equal(error.code, 'not_paired');
      return true;
    });
    assert.equal(pkexecSpawns.length, 0, 'an unpaired phone start never calls pkexec');

    // A direct start is the one step that calls pkexec. The stand-in runs the
    // engine as this user, so the engine refuses at its privilege check, and
    // the confirmed stop returns the app to the user engine.
    await assert.rejects(backend.start({ mode: 'direct' }), (error) => error.code === 'admin_required');
    assert.equal(pkexecSpawns.length, 1);
    assert.equal(pkexecSpawns[0].command, sandbox.pkexec);
    assert.deepEqual(pkexecSpawns[0].args, [sandbox.helper]);
    assert.deepEqual(pkexecSpawns[0].stdio, ['pipe', 'pipe', 'pipe'], 'direct mode passes no handoff');
    const rootPid = Number(fs.readFileSync(sandbox.pidFile, 'utf8'));
    assert.equal(await gone(rootPid), true, 'the helper-started engine stopped');
    assert.equal(backend.session().elevated, false);
    assert.equal((await backend.status()).platform.admin, false, 'status is back on the user engine');
    assert.equal(alive(userClient.pid), true, 'the user engine kept running');

    const result = await backend.dispose();
    assert.deepEqual(result, { stopped: true, timedOut: false });
    assert.equal(stopFailureKind(result, true), '');
  } finally {
    await backend.dispose();
    sandbox.remove();
  }
  assert.deepEqual(networkSnapshot(), before, 'the interface list and routes did not change');
});
