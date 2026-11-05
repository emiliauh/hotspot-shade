import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { wireLifecycle } = require('../src/main/lifecycle.js');

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

  stop.resolve();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(app.quitCalls, 1);

  const final = quitEvent();
  handlers['before-quit'](final);
  assert.equal(final.prevented, false);
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
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(app.quitCalls, 1);
  assert.equal(seen.message, 'stop failed');
});

test('demo mode quits at once and disposes in will-quit', () => {
  const { app, handlers } = fakeApp();
  let disposed = 0;
  let unregistered = 0;
  wireLifecycle({
    app,
    backend: { dispose() { disposed += 1; } },
    engineMode: false,
    unregister() { unregistered += 1; }
  });
  const event = quitEvent();
  handlers['before-quit'](event);
  assert.equal(event.prevented, false);
  assert.equal(disposed, 0);
  handlers['will-quit']();
  assert.equal(disposed, 1);
  assert.equal(unregistered, 1);
});

test('the quit path accepts a missing backend', async () => {
  const { app, handlers } = fakeApp();
  wireLifecycle({ app, engineMode: true });
  const event = quitEvent();
  handlers['before-quit'](event);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(app.quitCalls, 1);
});
