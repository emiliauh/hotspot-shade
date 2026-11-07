import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

// Exercise the page's real action with a controlled bridge and status read.
// The renderer is an IIFE, so extract this one action without initializing an
// Electron window or replacing its internal implementation with a fake.
const source = fs.readFileSync(new URL('../src/renderer/app.js', import.meta.url), 'utf8');
const start = source.indexOf('  function checkNow() {');
const end = source.indexOf('\n  function applyScenario()', start);
assert.ok(start >= 0 && end > start, 'the check action must be present');
const actionSource = '(' + source.slice(start, end).trim() + ')';

function harness(initialStatus, refreshedStatus, readFails = false) {
  const state = { busy: null, status: initialStatus, startMode: 'phone', hasStatus: true, failureSince: null };
  const calls = [];
  const messages = [];
  const check = vm.runInNewContext(actionSource, {
    state,
    object: value => value || {},
    bridgeReady: () => true,
    beginAction: () => { state.busy = 'check'; },
    call: name => { calls.push(name); return Promise.resolve(); },
    refreshStatus: () => {
      if (readFails) state.failureSince = 1;
      else state.status = refreshedStatus;
      return Promise.resolve();
    },
    toast: (title, detail) => { messages.push([title, detail]); },
    wording: first => first,
    errorCode: () => '',
    errorMessage: () => '',
    render: () => {},
    failAction: () => { throw new Error('unexpected action failure'); }
  });
  return { state, calls, messages, check };
}

test('checking an uncertain engine refreshes status without a source probe', async () => {
  const h = harness({ running: true, state: 'unknown' }, { running: true, state: 'unknown' });
  assert.equal(await h.check(), false);
  assert.deepEqual(h.calls, []);
  assert.equal(h.messages[0][0], 'Status unavailable');
});

test('a failed status read cannot produce a successful check', async () => {
  const h = harness({ running: false, paired: true }, null, true);
  assert.equal(await h.check(), false);
  assert.deepEqual(h.calls, ['probe']);
  assert.equal(h.messages[0][0], 'The check did not finish');
});

test('a source probe followed by uncertain engine status is not reported as success', async () => {
  const h = harness({ running: false, paired: true }, { running: true, state: 'unknown' });
  assert.equal(await h.check(), false);
  assert.deepEqual(h.calls, ['probe']);
  assert.equal(h.messages[0][0], 'Status unavailable');
});

test('direct mode checks engine status without probing a source device', async () => {
  const h = harness({ running: false }, { running: false });
  h.state.startMode = 'direct';
  assert.equal(await h.check(), true);
  assert.deepEqual(h.calls, []);
  assert.equal(h.messages[0][0], 'Status updated');
});

test('blocked cleanup and a running direct tunnel never probe the source', async () => {
  for (const status of [
    { running: true, cleanup_blocked: true },
    { running: true, mode: 'tun' }
  ]) {
    const h = harness(status, status);
    await h.check();
    assert.deepEqual(h.calls, []);
  }
});
