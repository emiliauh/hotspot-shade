import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

/* The packaged session backend with fake engine clients. No process, socket,
 * helper, or privilege is used. */

const require = createRequire(import.meta.url);
const { createSessionBackend, CLEANUP_MESSAGE, confirmedStop } = require('../src/backend/session-backend.js');
const { BackendError } = require('../src/backend/errors.js');

const HANDOFF = Object.freeze({ label: 'user engine handoff socket' });

function fakeUser(overrides = {}) {
  const calls = [];
  const state = { paired: true, running: false };
  const client = {
    calls,
    state,
    handoffStream: HANDOFF,
    started: 0,
    start() { client.started += 1; return Promise.resolve({}); },
    async call(operation) {
      calls.push(operation);
      if (overrides[operation]) return overrides[operation]();
      if (operation === 'status') return { source: 'user', running: false, paired: state.paired, state: 'idle' };
      if (operation === 'pairState') return { source: 'user', state: state.paired ? 'paired' : 'idle' };
      if (operation === 'handoff') {
        if (!state.paired) throw new BackendError('not_paired', 'not_paired', 409);
        return { ok: true };
      }
      if (operation === 'stop') return { source: 'user', running: false };
      return { source: 'user', operation };
    },
    stop: async () => ({ stopped: true, timedOut: false }),
    describe: () => ({ connected: true, transport: 'loopback_http', operations: ['status'] })
  };
  return client;
}

function fakeRoot(options = {}) {
  const calls = [];
  let running = false;
  let exit = null;
  const client = {
    calls,
    async start() {
      if (options.startError) throw options.startError;
      if (options.startGate) await options.startGate;
      if (client.stopped) throw new BackendError('engine_stopped', 'The engine is stopping.');
      return {};
    },
    async call(operation) {
      calls.push(operation);
      if (operation === 'status') {
        if (options.statusError) throw options.statusError;
        return { source: 'root', running, paired: true, state: running ? 'running' : 'idle' };
      }
      if (operation === 'start') {
        if (options.engineStartError) throw options.engineStartError;
        running = true;
        return { source: 'root', running: true };
      }
      if (operation === 'stop') { running = false; return { running: false }; }
      return { source: 'root', operation };
    },
    stopped: false,
    async stop() {
      client.stopped = true;
      running = options.keepRunning === true ? running : false;
      return options.stopResult || { stopped: true, timedOut: false };
    },
    exitInfo: () => exit,
    setExit(value) { exit = value; },
    setRunning(value) { running = value; },
    describe: () => ({ connected: true, transport: 'privileged_pkexec' })
  };
  return client;
}

function session(user, roots) {
  const created = [];
  const backend = createSessionBackend({
    userClient: user,
    createRootClient(handoffStream) {
      const next = roots.shift();
      assert.ok(next, 'an unexpected root engine launch');
      created.push({ handoffStream, client: next });
      return next;
    }
  });
  return { backend, created };
}

test('opening and using the app touches only the user engine', async () => {
  const user = fakeUser();
  const { backend, created } = session(user, []);
  assert.equal((await backend.status()).source, 'user');
  assert.equal((await backend.pairState()).source, 'user');
  await backend.beginPairing();
  await backend.cancelPairing();
  await backend.forget();
  await backend.failures();
  await backend.diagnostics();
  await backend.activity({ since: 0 });
  await backend.probe();
  assert.equal(created.length, 0, 'no root engine and no pkexec before a tunnel start');
  assert.deepEqual(user.calls, ['status', 'pairState', 'pair', 'pairCancel', 'forget', 'failures', 'diagnostics', 'activity', 'probe']);
  assert.equal(backend.describeEngine().privileged, false);
  assert.equal(backend.describeEngine().transport, 'loopback_http');
});

test('a phone start hands the pairing to one root engine, which then serves status', async () => {
  const user = fakeUser();
  const root = fakeRoot();
  const { backend, created } = session(user, [root]);
  const started = await backend.start({ mode: 'phone', ping: true });
  assert.equal(started.running, true);
  assert.equal(created.length, 1);
  assert.equal(created[0].handoffStream, HANDOFF, 'the user engine socket passes through unread');
  assert.ok(user.calls.indexOf('handoff') !== -1);
  assert.deepEqual(root.calls, ['start']);
  assert.equal((await backend.status()).source, 'root');
  assert.equal((await backend.pairState()).source, 'root');
  assert.equal((await backend.diagnostics()).source, 'root');
  assert.equal(backend.describeEngine().privileged, true);
  // A live root tunnel refuses pairing and forget.
  await assert.rejects(backend.beginPairing(), (error) => error.code === 'tunnel_running');
  await assert.rejects(backend.forget(), (error) => error.code === 'forget_blocked' && error.status === 409);
  assert.equal(user.calls.indexOf('pair'), -1);
  assert.equal(user.calls.indexOf('forget'), -1);
});

test('a confirmed stop returns to the user engine with the pairing kept', async () => {
  const user = fakeUser();
  const root = fakeRoot();
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'phone' });
  const after = await backend.stop();
  assert.equal(after.source, 'user');
  assert.ok(root.calls.indexOf('stop') !== -1, 'the root engine got its own stop first');
  assert.equal(root.stopped, true, 'the helper session was closed');
  const status = await backend.status();
  assert.equal(status.source, 'user');
  assert.equal(status.paired, true);
  assert.equal(backend.session().elevated, false);
});

test('an unpaired phone start is refused before pkexec', async () => {
  const user = fakeUser();
  user.state.paired = false;
  const { backend, created } = session(user, []);
  await assert.rejects(backend.start({ mode: 'phone' }), (error) => {
    assert.equal(error.code, 'not_paired');
    assert.match(error.message, /Pair with the source device first/);
    return true;
  });
  assert.equal(created.length, 0);
});

test('a direct start passes no handoff', async () => {
  const user = fakeUser();
  const root = fakeRoot();
  const { backend, created } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  assert.equal(created[0].handoffStream, null);
  assert.equal(user.calls.indexOf('handoff'), -1);
});

test('a denied or cancelled authorization returns to the user engine', async () => {
  const user = fakeUser();
  const denied = new BackendError('engine_start_failed', 'The privileged helper did not get authorization.');
  const root = fakeRoot({ startError: denied, stopResult: { stopped: true, timedOut: false, neverStarted: true } });
  const { backend } = session(user, [root]);
  await assert.rejects(backend.start({ mode: 'phone' }), (error) => error === denied);
  assert.equal(backend.session().elevated, false);
  assert.equal((await backend.status()).source, 'user');
});

test('a root engine that refuses the start is stopped and the error is kept', async () => {
  const user = fakeUser();
  const refusal = new BackendError('phone_auth', 'The source device rejected the token.');
  const root = fakeRoot({ engineStartError: refusal });
  const { backend } = session(user, [root]);
  await assert.rejects(backend.start({ mode: 'phone' }), (error) => error === refusal);
  assert.equal(root.stopped, true);
  assert.equal(backend.session().elevated, false);
});

test('an unconfirmed stop keeps the root engine as the status source and is never Off', async () => {
  const user = fakeUser();
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' } });
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'phone' });
  await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
  const status = await backend.status();
  assert.equal(status.source, 'root', 'the root engine stays the status source');
  assert.equal(status.running, false, 'the root engine says it is not running');
  assert.equal(status.state, 'unknown', 'but the app does not show Off');
  assert.equal(status.cleanup_blocked, true);
  assert.equal(status.error, CLEANUP_MESSAGE);
  await assert.rejects(backend.start({ mode: 'phone' }), (error) => error.code === 'engine_stop_incomplete');
  await assert.rejects(backend.beginPairing(), (error) => error.code === 'engine_stop_incomplete');
  await assert.rejects(backend.forget(), (error) => error.code === 'engine_stop_incomplete');
  // A lost or stopping root engine cannot answer, but the mark stays: the
  // status is the uncertain answer itself, so Try to turn off is still offered
  // and the page never shows an engine loss for it.
  root.call = async () => { throw new BackendError('engine_stopped', 'The engine stopped.'); };
  const lost = await backend.status();
  assert.equal(lost.state, 'unknown');
  assert.equal(lost.cleanup_blocked, true);
  assert.equal(lost.error, CLEANUP_MESSAGE);
  // Quit reports the unconfirmed root stop, not the clean user engine stop.
  const quit = await backend.dispose();
  assert.equal(quit.reason, 'helper_exit_timeout');
  assert.equal(confirmedStop(quit), false);
});

test('a helper that exits cleanly after a stop timeout is a late confirmation on the next stop', async () => {
  const user = fakeUser();
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' } });
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  await assert.rejects(backend.stop());
  // A non-zero exit is not a confirmation.
  root.setExit({ code: 5, signal: null });
  await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
  root.setExit({ code: 0, signal: null });
  const after = await backend.stop();
  assert.equal(after.source, 'user');
  assert.equal(backend.session().cleanupPending, false);
  assert.equal((await backend.status()).source, 'user');
});

test('an auto-stopped root engine is stopped through the helper before pairing, forget, or a new start', async () => {
  const user = fakeUser();
  const first = fakeRoot();
  const second = fakeRoot();
  const { backend, created } = session(user, [first, second]);
  await backend.start({ mode: 'phone' });
  first.setRunning(false); // hotspot_lost inside the root engine
  assert.equal((await backend.status()).source, 'root', 'the automatic stop reason comes from the root engine');
  await backend.start({ mode: 'phone' });
  assert.equal(first.stopped, true);
  assert.equal(created.length, 2);
  second.setRunning(false);
  await backend.forget();
  assert.equal(second.stopped, true);
  assert.ok(user.calls.indexOf('forget') !== -1);
  assert.equal(backend.session().elevated, false);
});

test('a stop during the authorization prompt cancels the start', async () => {
  const user = fakeUser();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const root = fakeRoot({ startGate: gate, stopResult: { stopped: true, timedOut: false, neverStarted: true } });
  const { backend } = session(user, [root]);
  const starting = backend.start({ mode: 'phone' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(backend.session().starting, true);
  // Status during the prompt still comes from the user engine.
  assert.equal((await backend.status()).source, 'user');
  const stopping = backend.stop();
  release();
  await assert.rejects(starting, (error) => error.code === 'engine_stopped' || error.code === 'start_cancelled');
  const after = await stopping;
  assert.equal(after.source, 'user');
  assert.equal(root.calls.indexOf('start'), -1, 'the root engine never started a tunnel');
  assert.equal(backend.session().elevated, false);
});

test('a start after quit begins starts nothing', async () => {
  const user = fakeUser();
  const { backend, created } = session(user, []);
  const result = await backend.dispose();
  assert.deepEqual(result, { stopped: true, timedOut: false });
  await assert.rejects(backend.start({ mode: 'phone' }), (error) => error.code === 'engine_stopped');
  assert.equal(created.length, 0);
});

test('quit stops the root engine before the user engine', async () => {
  const order = [];
  const user = fakeUser();
  user.stop = async () => { order.push('user'); return { stopped: true, timedOut: false }; };
  const root = fakeRoot();
  const rootStop = root.stop;
  root.stop = async () => { order.push('root'); return rootStop(); };
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'phone' });
  const result = await backend.dispose();
  assert.deepEqual(order, ['root', 'user']);
  assert.equal(confirmedStop(result), true);
});

/* Review finding: a stop during the authorization prompt times out as
 * authorization_unconfirmed. A later helper exit that proves no engine ran
 * must clear the mark on the next stop or start; an exit after an engine port
 * must not. */
test('a dismissed prompt after a prompt-time stop is confirmed later, but not after an engine port', async () => {
  for (const seen of [false, true]) {
    const user = fakeUser();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const root = fakeRoot({
      startGate: gate,
      stopResult: { stopped: false, timedOut: true, failed: true, reason: 'authorization_unconfirmed' }
    });
    root.engineSeen = seen;
    root.outputSettled = true;
    const next = fakeRoot();
    const { backend, created } = session(user, [root, next]);
    const starting = backend.start({ mode: 'phone' });
    await new Promise((resolve) => setImmediate(resolve));
    await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
    release();
    await assert.rejects(starting);
    assert.equal(backend.session().cleanupPending, true);
    assert.equal((await backend.status()).state, 'unknown', 'never shown as Off while unconfirmed');
    // pkexec later exits 127: the person dismissed the prompt.
    root.setExit({ code: 127, signal: null });
    if (seen) {
      await assert.rejects(backend.start({ mode: 'phone' }), (error) => error.code === 'engine_stop_incomplete');
      await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
      assert.equal(created.length, 1);
    } else {
      const started = await backend.start({ mode: 'phone' });
      assert.equal(started.running, true, 'the late confirmation allowed a new start');
      assert.equal(created.length, 2);
    }
  }
});

test('a start is refused while pairing or forget is in flight, so a handoff never carries a changing pairing', async () => {
  let finishForget;
  const user = fakeUser({
    forget: () => new Promise((resolve) => { finishForget = () => resolve({ ok: true }); })
  });
  const { backend, created } = session(user, [fakeRoot()]);
  const forgetting = backend.forget();
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(backend.start({ mode: 'phone' }), (error) => error.code === 'pairing_busy');
  finishForget();
  await forgetting;
  assert.equal(created.length, 0);
  assert.equal(user.calls.indexOf('handoff'), -1);

  const pairing = fakeUser({ pairState: async () => ({ state: 'confirm' }) });
  const second = session(pairing, [fakeRoot()]);
  await assert.rejects(second.backend.start({ mode: 'phone' }), (error) => error.code === 'pairing_busy');
  assert.equal(pairing.calls.indexOf('handoff'), -1, 'no handoff during a running pairing');
  assert.equal(second.created.length, 0);
});

test('a stop that settles the root session during a forget status read does not crash the forget', async () => {
  const user = fakeUser();
  const root = fakeRoot();
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'phone' });
  root.setRunning(false);
  const originalCall = root.call;
  let stopping = null;
  root.call = async (operation) => {
    if (operation === 'status' && !stopping) {
      stopping = backend.stop();
      await stopping;
    }
    return originalCall(operation);
  };
  await backend.forget();
  await stopping;
  assert.ok(user.calls.indexOf('forget') !== -1);
  assert.equal(backend.session().elevated, false);
});

test('a confirmed root stop does not read the user engine, so a dead user engine is not a failed stop', async () => {
  const user = fakeUser();
  const root = fakeRoot();
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'phone' });
  user.call = async () => { throw new BackendError('engine_stopped', 'The engine stopped unexpectedly.'); };
  const after = await backend.stop();
  assert.deepEqual({ ...after }, { source: 'user', running: false, stopped: true });
  assert.equal(backend.session().elevated, false);
  /* The next poll reports the engine loss on its own. */
  await assert.rejects(backend.status(), (error) => error.code === 'engine_stopped');
});

test('a late confirmation also returns the fixed answer when the user engine is gone', async () => {
  const user = fakeUser();
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' } });
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  await assert.rejects(backend.stop());
  root.setExit({ code: 0, signal: null });
  user.call = async () => { throw new BackendError('engine_stopped', 'The engine stopped unexpectedly.'); };
  const after = await backend.stop();
  assert.equal(after.stopped, true);
  assert.equal(backend.session().cleanupPending, false);
});

test('a status read clears a mark when the helper later exited 0 after a stop timeout', async () => {
  const user = fakeUser();
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' } });
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  await assert.rejects(backend.stop());
  const marked = await backend.status();
  assert.equal(marked.cleanup_blocked, true);
  assert.equal(backend.session().cleanupPending, true);
  root.setExit({ code: 0, signal: null });
  const status = await backend.status();
  assert.equal(status.source, 'user', 'the status read evaluated the helper exit with no stop request');
  assert.notEqual(status.cleanup_blocked, true);
  assert.equal(backend.session().cleanupPending, false);
  assert.equal(backend.session().elevated, false);
});

test('a status read clears a mark when pkexec was refused during the prompt (exit 126, no engine)', async () => {
  const user = fakeUser();
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: false, failed: true, reason: 'authorization_unconfirmed' } });
  root.engineSeen = false;
  root.outputSettled = true;
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  await assert.rejects(backend.stop());
  root.setExit({ code: 126, signal: null });
  assert.equal((await backend.status()).source, 'user');
  assert.equal(backend.session().cleanupPending, false);
});

test('a status read leaves the mark for a non-zero helper exit and while a stop attempt is running', async () => {
  const user = fakeUser();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' } });
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  await assert.rejects(backend.stop());
  root.setExit({ code: 5, signal: null });
  assert.equal((await backend.status()).cleanup_blocked, true);
  root.setExit({ code: 0, signal: null });
  /* A retry that is still running decides for itself; the poll never waits for it. */
  root.retryStop = async () => { await gate; return { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' }; };
  root.setExit(null);
  const retrying = backend.stop();
  await new Promise((resolve) => setImmediate(resolve));
  root.setExit({ code: 0, signal: null });
  const during = await backend.status();
  assert.equal(during.cleanup_blocked, true, 'the status read did not clear an attempt in flight');
  release();
  await assert.rejects(retrying, (error) => error.code === 'engine_stop_incomplete');
  assert.equal((await backend.status()).source, 'user', 'the next read sees the exit and clears the mark');
});

test('a later Turn off re-attempts an unconfirmed stop instead of replaying the cached result', async () => {
  const user = fakeUser();
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' } });
  let retries = 0;
  root.retryStop = async () => {
    retries += 1;
    return retries === 1
      ? { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' }
      : { stopped: true, timedOut: false };
  };
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
  assert.equal(retries, 0, 'the first attempt uses the normal stop');
  await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
  assert.equal(retries, 1);
  const after = await backend.stop();
  assert.equal(after.stopped, true);
  assert.equal(retries, 2);
  assert.equal(backend.session().cleanupPending, false);
  assert.equal(backend.session().elevated, false);
});

test('a stop that is still in flight is shared, not retried', async () => {
  const user = fakeUser();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const root = fakeRoot();
  root.stop = async () => { await gate; return { stopped: true, timedOut: false }; };
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  const first = backend.stop();
  const second = backend.stop();
  assert.equal(first, second);
  release();
  await first;
});

test('a status read that began before Turn on never publishes the user engine answer once the root is live', async () => {
  const user = fakeUser();
  const root = fakeRoot();
  let answers = 0;
  let releaseFirst;
  const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
  user.call = async function (operation) {
    user.calls.push(operation);
    if (operation === 'status') {
      answers += 1;
      if (answers === 1) {
        await firstGate;
        return { source: 'user', running: false, paired: true, state: 'idle' };
      }
      return { source: 'user', running: false, paired: true, state: 'idle' };
    }
    if (operation === 'pairState') return { source: 'user', state: 'paired' };
    if (operation === 'handoff') return { ok: true };
    return { source: 'user', operation };
  };
  const { backend } = session(user, [root]);
  const stale = backend.status();
  await new Promise((resolve) => setImmediate(resolve));
  await backend.start({ mode: 'phone' });
  assert.equal(backend.session().ready, true);
  releaseFirst();
  const value = await stale;
  assert.equal(value.source, 'root', 'the stale user answer was dropped and the root read replaced it');
  assert.equal(value.running, true);
});

test('a status read that began on the root engine is dropped when a stop returns the app to the user engine', async () => {
  const user = fakeUser();
  const root = fakeRoot();
  let releaseRead;
  const readGate = new Promise((resolve) => { releaseRead = resolve; });
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'phone' });
  const originalCall = root.call;
  let held = false;
  root.call = async function (operation) {
    if (operation === 'status' && !held) {
      held = true;
      await readGate;
      return { source: 'root', running: true, paired: true, state: 'running' };
    }
    return originalCall.call(root, operation);
  };
  const stale = backend.status();
  await new Promise((resolve) => setImmediate(resolve));
  await backend.stop();
  releaseRead();
  const value = await stale;
  assert.equal(value.source, 'user', 'a running true answer from the closed root engine is not published');
  assert.equal(value.running, false);
});

test('an unconfirmed stop of a ready root answers a status read even when the real client throws while stopping', async () => {
  const user = fakeUser();
  const root = fakeRoot({ stopResult: { stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' } });
  const { backend } = session(user, [root]);
  await backend.start({ mode: 'direct' });
  const originalStop = root.stop;
  root.stop = async function () {
    const result = await originalStop.call(root);
    /* Like the real client: once stopping, every call is refused. */
    root.call = async () => { throw new BackendError('engine_stopped', 'The engine is stopping.'); };
    return result;
  };
  await assert.rejects(backend.stop(), (error) => error.code === 'engine_stop_incomplete');
  const status = await backend.status();
  assert.equal(status.cleanup_blocked, true);
  assert.equal(status.state, 'unknown');
  assert.equal(status.error, CLEANUP_MESSAGE);
});

test('a failed status read of a live root never stops it for pairing, forget, or a start', async () => {
  for (const code of ['engine_timeout', 'engine_unavailable']) {
    const user = fakeUser();
    const root = fakeRoot();
    const { backend } = session(user, [root]);
    await backend.start({ mode: 'phone' });
    const originalCall = root.call;
    root.call = async function (operation) {
      if (operation === 'status') throw new BackendError(code, 'The engine did not answer.');
      return originalCall.call(root, operation);
    };
    await assert.rejects(backend.beginPairing(), (error) => error.code === 'tunnel_running');
    await assert.rejects(backend.forget(), (error) => error.code === 'forget_blocked');
    await assert.rejects(backend.start({ mode: 'phone' }), (error) => error.code === 'status_unavailable');
    assert.equal(root.stopped, false, 'the live tunnel was not stopped');
    assert.equal(backend.session().elevated, true);
    root.call = originalCall;
    await backend.stop();
  }
});

test('a root engine that reports it stopped is stopped through the helper for pairing and a new start', async () => {
  const user = fakeUser();
  const first = fakeRoot();
  const second = fakeRoot();
  const { backend } = session(user, [first, second]);
  await backend.start({ mode: 'phone' });
  first.call = async () => { throw new BackendError('engine_stopped', 'The engine stopped unexpectedly.'); };
  await backend.beginPairing();
  assert.equal(first.stopped, true);
  assert.equal(backend.session().elevated, false);
});

test('a status read that keeps changing hands is not published as a stale answer', async () => {
  const user = fakeUser();
  const gates = [];
  user.call = async function (operation) {
    if (operation !== 'status') return { source: 'user', operation };
    await new Promise((resolve) => gates.push(resolve));
    return { source: 'user', running: false, paired: true, state: 'idle' };
  };
  const { backend } = session(user, [fakeRoot(), fakeRoot(), fakeRoot(), fakeRoot()]);
  const pending = backend.status();
  for (let round = 0; round < 3; round += 1) {
    await new Promise((resolve) => setImmediate(resolve));
    /* A stop begins and bumps the generation while the read is in flight. */
    const stopping = backend.stop().catch(() => {});
    gates.splice(0).forEach((open) => open());
    await stopping;
  }
  await assert.rejects(pending, (error) => error.code === 'status_changed');
});
