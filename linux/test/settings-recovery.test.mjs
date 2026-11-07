import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';

const model = createRequire(import.meta.url)('../src/renderer/model.js');
const source = fs.readFileSync(new URL('../src/renderer/app.js', import.meta.url), 'utf8');
const start = source.indexOf('  function renderSettings(derived) {');
const end = source.indexOf('\n  function renderActivity()', start);
assert.ok(start >= 0 && end > start, 'the Settings renderer must be present');

function render(status, freshness = 'fresh', busy = null, stopError = '') {
  const state = {
    status, pair: { state: 'idle' }, busy, ping: false, settings: {},
    bridgeState: 'ready', forgetBlocked: false, error: stopError,
    retryAction: stopError ? 'stop' : null
  };
  const dom = new Proxy({}, {
    get(target, key) {
      if (!target[key]) target[key] = {};
      return target[key];
    }
  });
  const derived = model.deriveDashboard({ status, hasStatus: true, pair: state.pair, freshness, busy });
  const fn = vm.runInNewContext('(' + source.slice(start, end).trim() + ')', {
    state, dom, model,
    object: value => value && typeof value === 'object' ? value : {},
    text: value => typeof value === 'string' ? value : '',
    bridgeReady: () => true,
    setText: (node, value) => { node.textContent = value; },
    engineMode: () => true,
    renderPrivacy: () => {}
  });
  fn(derived);
  return dom;
}

test('Settings offers a stop attempt without offering Forget during recovery', () => {
  for (const recovery of [{ state: 'unknown' }, { cleanup_blocked: true }]) {
    const dom = render({ running: true, paired: true, ...recovery });
    assert.equal(dom.settingsTryStop.hidden, false);
    assert.equal(dom.settingsTryStop.disabled, false);
    assert.equal(dom.settingsForget.hidden, true);
    assert.equal(dom.settingsTurnOffForget.hidden, true);
  }
});

test('Settings hides stale attempts and disables them during an action', () => {
  const status = { running: true, paired: true, state: 'unknown' };
  assert.equal(render(status, 'stale').settingsTryStop.hidden, true);
  assert.equal(render(status, 'fresh', 'stop').settingsTryStop.disabled, true);
  assert.equal(render({ running: true, paired: true }).settingsTryStop.hidden, true);
});

test('Settings retains the stop failure while the status remains uncertain', () => {
  const dom = render({ running: true, paired: true, state: 'unknown' }, 'fresh', null, 'Cleanup is uncertain.');
  assert.equal(dom.settingsPairingMessage.textContent, 'Cleanup is uncertain.');
});

test('the actual Settings button is registered and calls stop without forgetting', () => {
  const html = fs.readFileSync(new URL('../src/renderer/index.html', import.meta.url), 'utf8');
  assert.match(html, /id="settingsTryStop"/);
  assert.match(source, /'settingsTurnOffForget', 'settingsTryStop'/);
  const match = source.match(/dom\.settingsTryStop\.addEventListener\('click', function \(\) \{([\s\S]*?)\}\);/);
  assert.ok(match, 'the Settings stop button must have a click handler');
  const calls = [];
  vm.runInNewContext('(function () {' + match[1] + '})()', {
    stopTunnel: value => calls.push(['stop', value]),
    stopAndForget: () => calls.push(['forget'])
  });
  assert.deepEqual(calls, [['stop', false]]);
});
