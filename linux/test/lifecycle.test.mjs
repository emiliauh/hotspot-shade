import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  AUTHORIZATION_UNCONFIRMED_NOTICE,
  CLEANUP_UNCONFIRMED_NOTICE,
  ENGINE_RUNNING_NOTICE,
  STOP_FAILED_NOTICE,
  STOP_TIMEOUT_NOTICE,
  disposeBackend,
  stopFailureKind,
  wireLifecycle
} = require('../src/main/lifecycle.js');

test('a monitor failure cannot prevent the backend stop', async () => {
  const result = { stopped: true, timedOut: false };
  let stops = 0;
  const value = disposeBackend(
    { stop() { throw new Error('monitor failure'); } },
    { dispose() { stops += 1; return Promise.resolve(result); } },
    () => { throw new Error('report failure'); }
  );
  assert.deepEqual(await value, result);
  assert.equal(stops, 1);
});
const { createQuitNoticeReporter } = require('../src/main/quit-notice.js');

function fakeApp() {
  const handlers = {};
  const app = {
    quitCalls: 0,
    on(event, handler) { handlers[event] = handler; },
    quit() { app.quitCalls += 1; }
  };
  return { app, handlers };
}

function quitEvent() {
  return { prevented: false, preventDefault() { this.prevented = true; } };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('a cleanup failure reaches the fixed native warning before quit', async () => {
  const { app, handlers } = fakeApp();
  const events = [];
  app.quit = () => { events.push('quit'); };
  const report = createQuitNoticeReporter({
    showMessageBoxSync(options) { events.push(options); }
  }, () => {});
  wireLifecycle({
    app,
    engineMode: true,
    backend: { dispose() { return { stopped: false, failed: true, reason: 'engine_cleanup_failed' }; } },
    report
  });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(events.length, 2);
  assert.deepEqual(events[0], {
    type: 'warning', buttons: ['OK'], defaultId: 0, cancelId: 0, noLink: true,
    title: CLEANUP_UNCONFIRMED_NOTICE.title,
    message: CLEANUP_UNCONFIRMED_NOTICE.message,
    detail: CLEANUP_UNCONFIRMED_NOTICE.detail
  });
  assert.equal(events[1], 'quit');
});

function notices() {
  const seen = [];
  return {
    seen,
    report(notice) { seen.push(notice); }
  };
}

test('engine mode stops the engine before the app quits', async () => {
  const { app, handlers } = fakeApp();
  const stop = deferred();
  let disposed = 0;
  wireLifecycle({
    app,
    backend: { dispose() { disposed += 1; return stop.promise; } },
    engineMode: () => true,
    unregister() {}
  });

  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, true);
  assert.equal(disposed, 1);
  assert.equal(app.quitCalls, 0);

  /* A second quit request while the engine stops does not start a second stop. */
  const second = quitEvent();
  handlers['before-quit'](second);
  assert.equal(second.prevented, true);
  assert.equal(disposed, 1);

  stop.resolve({ stopped: true, timedOut: false });
  await flush();
  assert.equal(app.quitCalls, 1);

  const final = quitEvent();
  handlers['before-quit'](final);
  assert.equal(final.prevented, false);
});

test('a clean structured stop shows no notice', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({
    app,
    backend: { dispose() { return Promise.resolve({ stopped: true, timedOut: false }); } },
    engineMode: true,
    report: seen.report
  });
  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, true);
  await flush();
  assert.equal(app.quitCalls, 1);
  assert.deepEqual(seen.seen, []);
});

test('a synchronous clean result shows no notice', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({
    app,
    backend: { dispose() { return { stopped: true, timedOut: false }; } },
    engineMode: true,
    report: seen.report
  });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(app.quitCalls, 1);
  assert.deepEqual(seen.seen, []);
});

test('an asynchronous failed stop is reported with fixed text before the quit', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  let quitCallsAtReport = null;
  wireLifecycle({
    app,
    backend: {
      dispose() {
        return Promise.resolve({
          stopped: false,
          failed: true,
          timedOut: false,
          reason: 'helper_signaled',
          helperCode: 4,
          helperSignal: 'SIGTERM'
        });
      }
    },
    engineMode: true,
    report(notice) {
      quitCallsAtReport = app.quitCalls;
      seen.report(notice);
    }
  });
  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, true);
  await flush();
  assert.equal(seen.seen.length, 1);
  assert.equal(seen.seen[0].kind, 'stop_failed');
  assert.equal(seen.seen[0].message, STOP_FAILED_NOTICE.message);
  assert.equal(seen.seen[0].detail, STOP_FAILED_NOTICE.detail);
  /* The notice is shown before the app quits. */
  assert.equal(quitCallsAtReport, 0);
  assert.equal(app.quitCalls, 1);
  /* The reason and the helper exit values stay out of the notice. */
  const text = JSON.stringify(seen.seen[0]);
  assert.equal(text.includes('helper_signaled'), false);
  assert.equal(text.includes('SIGTERM'), false);
  /* No claim that cleanup happened. */
  assert.match(seen.seen[0].detail, /may still hold the tunnel/);
  assert.equal(/removed|released|cleaned|released the lock/.test(seen.seen[0].detail), false);
});

test('a synchronous failed result is reported before the quit', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({
    app,
    backend: { dispose() { return { stopped: false, failed: true, reason: 'helper_failed' }; } },
    engineMode: true,
    report: seen.report
  });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(seen.seen.length, 1);
  assert.equal(seen.seen[0].kind, 'stop_failed');
  assert.equal(app.quitCalls, 1);
});

test('a stop timeout is reported as a timeout', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({
    app,
    backend: {
      dispose() {
        return Promise.resolve({
          stopped: false,
          failed: true,
          timedOut: true,
          reason: 'engine_stop_timeout'
        });
      }
    },
    engineMode: true,
    report: seen.report
  });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(seen.seen.length, 1);
  assert.equal(seen.seen[0].kind, 'stop_timeout');
  assert.equal(seen.seen[0].message, 'The stop did not finish in time.');
  assert.equal(seen.seen[0].message, STOP_TIMEOUT_NOTICE.message);
  assert.equal(seen.seen[0].detail, STOP_TIMEOUT_NOTICE.detail);
  assert.equal(app.quitCalls, 1);
});

test('a failed engine stop does not block the quit', async () => {
  const { app, handlers } = fakeApp();
  let seen = null;
  wireLifecycle({
    app,
    backend: { dispose() { return Promise.reject(new Error('stop failed')); } },
    engineMode: true,
    onError(error) { seen = error; }
  });
  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, true);
  await flush();
  assert.equal(app.quitCalls, 1);
  assert.equal(seen.message, 'stop failed');
});

test('a rejected stop is reported and the quit continues', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  const errors = [];
  wireLifecycle({
    app,
    backend: { dispose() { return Promise.reject(new Error('stop failed with secret abc123')); } },
    engineMode: true,
    unregister() {},
    onError(error) { errors.push(error); },
    report: seen.report
  });
  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, true);
  await flush();
  assert.equal(app.quitCalls, 1);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].message, 'stop failed with secret abc123');
  assert.equal(seen.seen.length, 1);
  assert.equal(seen.seen[0].kind, 'stop_failed');
  assert.equal(JSON.stringify(seen.seen[0]).includes('abc123'), false);
});

test('a thrown dispose error is reported once and does not block the quit', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  let thrown = 0;
  wireLifecycle({
    app,
    backend: { dispose() { thrown += 1; throw new Error('token abc123'); } },
    engineMode: true,
    onError() {},
    report: seen.report
  });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(thrown, 1);
  assert.equal(app.quitCalls, 1);
  assert.equal(seen.seen.length, 1);
  assert.equal(JSON.stringify(seen.seen[0]).includes('abc123'), false);
});

test('a throwing error callback cannot hide a stop failure or block quit', async () => {
  for (const asynchronous of [false, true]) {
    const { app, handlers } = fakeApp();
    const seen = notices();
    wireLifecycle({
      app,
      backend: { dispose() {
        if (asynchronous) return Promise.reject(new Error('stop failed'));
        throw new Error('stop failed');
      } },
      engineMode: true,
      onError() { throw new Error('logging failed'); },
      report: seen.report
    });
    handlers['before-quit'](quitEvent());
    await flush();
    assert.equal(app.quitCalls, 1);
    assert.equal(seen.seen.length, 1);
    assert.equal(seen.seen[0].kind, 'stop_failed');
  }
});

test('duplicate quit requests and will-quit calls stop and report once', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  const stop = deferred();
  let disposed = 0;
  let unregistered = 0;
  const lifecycle = wireLifecycle({
    app,
    backend: {
      dispose() {
        disposed += 1;
        return stop.promise;
      }
    },
    engineMode: true,
    unregister() { unregistered += 1; },
    report: seen.report
  });

  handlers['before-quit'](quitEvent());
  handlers['before-quit'](quitEvent());
  handlers['will-quit']();
  assert.equal(disposed, 1);
  assert.equal(unregistered, 1);

  stop.resolve({ stopped: false, timedOut: true, failed: true, reason: 'helper_exit_timeout' });
  await flush();
  assert.equal(app.quitCalls, 1);

  handlers['will-quit']();
  handlers['will-quit']();
  await flush();
  assert.equal(disposed, 1);
  assert.equal(unregistered, 1);
  assert.equal(seen.seen.length, 1);
  assert.equal(seen.seen[0].kind, 'stop_timeout');
  assert.equal(seen.seen[0].message, 'The stop did not finish in time.');
  assert.match(seen.seen[0].detail, /privileged helper may still be running/);
  assert.equal(lifecycle.reported(), true);
  assert.equal(lifecycle.quitReady(), true);
});

test('a failing report function does not block the quit', async () => {
  const { app, handlers } = fakeApp();
  let reported = 0;
  wireLifecycle({
    app,
    backend: { dispose() { return Promise.resolve({ stopped: false, failed: true, reason: 'helper_failed' }); } },
    engineMode: true,
    report() {
      reported += 1;
      throw new Error('no display');
    }
  });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(reported, 1);
  assert.equal(app.quitCalls, 1);
});

test('demo mode quits at once and disposes in will-quit', () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  let disposed = 0;
  let unregistered = 0;
  wireLifecycle({
    app,
    backend: { dispose() { disposed += 1; } },
    engineMode: false,
    unregister() { unregistered += 1; },
    report: seen.report
  });
  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, false);
  assert.equal(disposed, 0);
  handlers['will-quit']();
  assert.equal(disposed, 1);
  assert.equal(unregistered, 1);
  assert.deepEqual(seen.seen, []);
});

test('demo mode reports a synchronous failed dispose in will-quit', () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({
    app,
    backend: { dispose() { return { stopped: false, failed: true, reason: 'engine_failed' }; } },
    engineMode: false,
    report: seen.report
  });
  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, false);
  assert.equal(seen.seen.length, 0);
  handlers['will-quit']();
  assert.equal(seen.seen.length, 1);
  assert.equal(seen.seen[0].kind, 'stop_failed');
});

test('a missing engine backend reports that stop is unconfirmed', async () => {
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({ app, engineMode: true, report: seen.report });
  const event = quitEvent();
  handlers['before-quit'](event);
  await flush();
  assert.equal(app.quitCalls, 1);
  assert.equal(seen.seen[0].kind, 'stop_failed');
});

test('engine quit requires an explicit clean stop result', async () => {
  for (const result of [undefined, null, {}, [], { timedOut: false }]) {
    const { app, handlers } = fakeApp();
    const seen = notices();
    wireLifecycle({ app, engineMode: true, backend: { dispose() { return result; } }, report: seen.report });
    handlers['before-quit'](quitEvent());
    await flush();
    assert.equal(app.quitCalls, 1);
    assert.equal(seen.seen[0].kind, 'stop_failed');
  }
});

test('a known unavailable engine reports that it never started', async () => {
  const { createUnavailableEngineBackend } = require('../src/backend/engine-backend.js');
  const backend = createUnavailableEngineBackend('not configured');
  assert.deepEqual(backend.dispose(), { stopped: true, timedOut: false, neverStarted: true });
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({ app, engineMode: true, backend, report: seen.report });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(app.quitCalls, 1);
  assert.deepEqual(seen.seen, []);
});

test('stopFailureKind trusts only a structured failure', () => {
  assert.equal(stopFailureKind(undefined), '');
  assert.equal(stopFailureKind({}), '');
  assert.equal(stopFailureKind({ stopped: true, timedOut: false }), '');
  assert.equal(stopFailureKind({ stopped: false }), 'stop_failed');
  assert.equal(stopFailureKind({ failed: true }), 'stop_failed');
  assert.equal(stopFailureKind({ timedOut: true }), 'stop_failed');
  assert.equal(stopFailureKind({ timedOut: true, failed: true, reason: 'engine_stop_timeout' }), 'stop_timeout');
  assert.equal(stopFailureKind({ timedOut: true, failed: true, reason: 'helper_exit_timeout' }), 'stop_timeout');
  assert.equal(stopFailureKind({ failed: true, reason: 'helper_signaled' }), 'stop_failed');
  assert.equal(stopFailureKind({ failed: true, reason: 'engine_stop_timeout ' }), 'stop_failed');
  assert.equal(stopFailureKind('failed'), '');
});

async function quitWith(result) {
  const { app, handlers } = fakeApp();
  const seen = notices();
  wireLifecycle({
    app,
    backend: { dispose() { return Promise.resolve(result); } },
    engineMode: true,
    report: seen.report
  });
  handlers['before-quit'](quitEvent());
  await flush();
  assert.equal(app.quitCalls, 1, 'the quit always continues');
  return seen.seen;
}

test('a helper that never started an engine shows no notice', async () => {
  for (const code of [126, 127, 7]) {
    const seen = await quitWith({
      stopped: true,
      timedOut: false,
      neverStarted: true,
      reason: code === 7 ? 'engine_authorization_canceled' : 'helper_failed',
      helperCode: code
    });
    assert.deepEqual(seen, [], 'exit code ' + code);
  }
});

test('a development engine that exits abnormally is reported with a cleanup warning', async () => {
  const seen = await quitWith({
    stopped: false,
    timedOut: false,
    failed: true,
    reason: 'engine_signaled',
    cleanupUnconfirmed: true
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0], CLEANUP_UNCONFIRMED_NOTICE);
  assert.equal(seen[0].kind, 'cleanup_unconfirmed');
  assert.match(seen[0].message, /could not confirm/);
  assert.match(seen[0].detail, /may remain/);
  assert.match(seen[0].detail, /Check the routes/);
  assert.equal(/helper/i.test(seen[0].message + seen[0].detail), false);
});

test('a development engine that is still running is reported as running', async () => {
  const seen = await quitWith({
    stopped: false,
    timedOut: false,
    stillRunning: true,
    failed: true,
    reason: 'engine_still_running'
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0], ENGINE_RUNNING_NOTICE);
  assert.match(seen[0].message, /still running/);
  assert.match(seen[0].detail, /without forcing it/);
  assert.equal(/helper/i.test(seen[0].message + seen[0].detail), false);
});

test('an unseen helper readiness is reported as unconfirmed, not as no engine', async () => {
  const seen = await quitWith({
    stopped: false,
    timedOut: true,
    failed: true,
    reason: 'authorization_unconfirmed'
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0], AUTHORIZATION_UNCONFIRMED_NOTICE);
  assert.equal(seen[0].kind, 'authorization_unconfirmed');
  const text = seen[0].message + ' ' + seen[0].detail;
  assert.match(text, /could confirm/);
  assert.match(text, /may still be running/);
  assert.match(text, /may still hold the tunnel/);
  assert.match(text, /check the engine and the routes/i);
  /* No assurance that the helper started no engine. */
  assert.equal(/set to start none|started no engine|no engine was started/i.test(text), false);
});

test('every fixed notice is plain, local, and free of secrets and exit values', () => {
  const all = [
    STOP_FAILED_NOTICE,
    STOP_TIMEOUT_NOTICE,
    CLEANUP_UNCONFIRMED_NOTICE,
    ENGINE_RUNNING_NOTICE,
    AUTHORIZATION_UNCONFIRMED_NOTICE
  ];
  const kinds = new Set(all.map((notice) => notice.kind));
  assert.equal(kinds.size, all.length);
  for (const notice of all) {
    assert.equal(Object.isFrozen(notice), true);
    const text = JSON.stringify(notice);
    assert.equal(/[0-9a-f]{32}/.test(text), false, 'no secret-like value');
    assert.equal(/SIG[A-Z]+|exit code|code [0-9]/.test(text), false, 'no signal or exit value');
    assert.equal(/[—–]/.test(text), false, 'no em or en dash');
    assert.equal(/removed|released|cleaned up/i.test(notice.detail), false, 'no cleanup claim');
  }
});

test('stopFailureKind separates a cleanup warning, a running engine, and an unconfirmed prompt', () => {
  assert.equal(stopFailureKind({ stopped: true, timedOut: false }), '');
  assert.equal(stopFailureKind({ stopped: true, neverStarted: true }), '');
  assert.equal(stopFailureKind({ neverStarted: true }, true), 'stop_failed');
  assert.equal(stopFailureKind({ stopped: false, failed: true, reason: 'engine_cleanup_failed' }, true), 'cleanup_unconfirmed');
  assert.equal(stopFailureKind({ stopped: false, failed: true, stillRunning: true }), 'engine_running');
  assert.equal(
    stopFailureKind({ stopped: false, failed: true, reason: 'engine_signaled', cleanupUnconfirmed: true }),
    'cleanup_unconfirmed'
  );
  assert.equal(
    stopFailureKind({ stopped: true, cleanupUnconfirmed: true }),
    'cleanup_unconfirmed',
    'an unconfirmed cleanup is never treated as a clean stop'
  );
  assert.equal(
    stopFailureKind({ stopped: false, timedOut: true, failed: true, reason: 'authorization_unconfirmed' }),
    'authorization_unconfirmed'
  );
  assert.equal(stopFailureKind({ stopped: false, failed: true, reason: 'helper_failed' }), 'stop_failed');
});
