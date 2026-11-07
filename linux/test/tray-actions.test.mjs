import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createTrayActionRunner } = require('../src/main/tray-actions.js');

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}

test('a synchronous backend throw reports once, releases busy, and does not retry', async () => {
  const calls = [];
  const failures = [];
  let throwNext = true;
  const runner = createTrayActionRunner({
    backend: {
      start(payload) {
        calls.push(payload);
        if (throwNext) {
          throwNext = false;
          throw new Error('The demo backend refused the start.');
        }
        return Promise.resolve({ running: true });
      },
      stop() {
        calls.push('stop');
        return Promise.resolve({ running: false });
      }
    },
    startPayload() {
      return { mode: 'phone', ping: true };
    },
    onFailure(kind, error) {
      failures.push({ kind, message: error.message });
    }
  });

  assert.equal(runner.run('start'), false);
  assert.equal(runner.isBusy(), false);
  assert.equal(calls.length, 1);
  assert.deepEqual(failures.map((entry) => entry.kind), ['start']);

  await wait(0);
  assert.equal(calls.length, 1, 'a failed action is never retried by itself');

  assert.equal(runner.run('start'), true);
  await wait(0);
  assert.equal(calls.length, 2);
  assert.equal(runner.isBusy(), false);
  assert.equal(failures.length, 1);
});

test('overlapping tray actions are ignored while one action is pending', async () => {
  const pending = deferred();
  const calls = [];
  const runner = createTrayActionRunner({
    backend: {
      start() {
        calls.push('start');
        return pending.promise;
      },
      stop() {
        calls.push('stop');
        return Promise.resolve({ running: false });
      }
    },
    startPayload() {
      return { mode: 'phone', ping: true };
    }
  });

  assert.equal(runner.run('start'), true);
  assert.equal(runner.isBusy(), true);
  assert.equal(runner.run('stop'), false);
  assert.equal(runner.run('start'), false);
  assert.deepEqual(calls, ['start']);

  pending.resolve({ running: true });
  await wait(0);
  assert.equal(runner.isBusy(), false);

  assert.equal(runner.run('stop'), true);
  await wait(0);
  assert.deepEqual(calls, ['start', 'stop']);
  assert.equal(runner.isBusy(), false);
});

test('an asynchronous rejection reports once, releases busy, and allows a later action', async () => {
  const failures = [];
  let calls = 0;
  const runner = createTrayActionRunner({
    backend: {
      start() {
        calls += 1;
        return Promise.resolve({ running: true });
      },
      stop() {
        calls += 1;
        return Promise.reject(new Error('The engine did not answer.'));
      }
    },
    startPayload() {
      return { mode: 'phone', ping: true };
    },
    onFailure(kind) {
      failures.push(kind);
    }
  });

  assert.equal(runner.run('stop'), true);
  await wait(0);
  assert.equal(runner.isBusy(), false);
  assert.deepEqual(failures, ['stop']);

  assert.equal(runner.run('start'), true);
  await wait(0);
  assert.equal(runner.isBusy(), false);
  assert.deepEqual(failures, ['stop']);
  assert.equal(calls, 2);
});

test('a throw while building the start payload is reported, not thrown into Electron', async () => {
  let started = 0;
  const failures = [];
  const runner = createTrayActionRunner({
    backend: {
      start() {
        started += 1;
        return Promise.resolve({});
      }
    },
    startPayload() {
      throw new Error('The settings file could not be read.');
    },
    onFailure(kind) {
      failures.push(kind);
    }
  });

  assert.equal(runner.run('start'), false);
  assert.equal(started, 0);
  assert.equal(runner.isBusy(), false);
  assert.deepEqual(failures, ['start']);
});

test('a status refresh failure is not reported as a failed action', async () => {
  const failures = [];
  const errors = [];
  const runner = createTrayActionRunner({
    backend: {
      start() {
        return Promise.resolve({ running: true });
      },
      stop() {
        return Promise.resolve({ running: false });
      }
    },
    startPayload() {
      return { mode: 'phone', ping: true };
    },
    refresh() {
      return Promise.reject(new Error('The status route did not answer.'));
    },
    onFailure(kind) {
      failures.push(kind);
    },
    onError(error) {
      errors.push(error.message);
    }
  });

  assert.equal(runner.run('start'), true);
  await wait(0);
  assert.equal(runner.isBusy(), false);
  assert.deepEqual(failures, []);
  assert.deepEqual(errors, ['The status route did not answer.']);

  assert.equal(runner.run('stop'), true);
  await wait(0);
  assert.equal(runner.isBusy(), false);
});

test('a throwing failure reporter does not leave the runner busy or escape', async () => {
  const errors = [];
  const runner = createTrayActionRunner({
    backend: {
      stop() {
        throw new Error('The tunnel could not stop.');
      }
    },
    onFailure() {
      throw new Error('The notification failed.');
    },
    onError(error) {
      errors.push(error.message);
    }
  });

  assert.equal(runner.run('stop'), false);
  assert.equal(runner.isBusy(), false);
  assert.deepEqual(errors, ['The notification failed.']);
});
