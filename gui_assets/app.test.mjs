// Focused tests for the failure presentation in app.js. The page has no build
// step and no module export. The test reads the real source and runs the pure
// failure helpers in an isolated context.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const helpersStart = source.indexOf('/* --------------------------- recent failures --------------------------- */');
const helpersEnd = source.indexOf('    function failureSummary(text) {', helpersStart);
const reportStart = source.indexOf('    function failureReportText(data) {');
const reportEnd = source.indexOf('    function failureReport() {', reportStart);
assert.ok(helpersStart > 0 && helpersEnd > helpersStart, 'failure helpers must stay together');
assert.ok(reportStart > helpersEnd && reportEnd > reportStart, 'the failure report must follow the helpers');

const context = {};
const stubs = `
function num(value) {
  var n = typeof value === 'number' ? value : parseFloat(value);
  return isFinite(n) ? n : 0;
}
function pickNumber(obj) {
  for (var i = 1; i < arguments.length; i++) {
    var key = arguments[i];
    if (obj && obj[key] !== undefined && obj[key] !== null) {
      var n = num(obj[key]);
      if (isFinite(n)) return n;
    }
  }
  return 0;
}
`;
const script = stubs +
  source.slice(helpersStart, helpersEnd) +
  source.slice(reportStart, reportEnd) +
  '\nglobalThis.__failureApi = {' +
  ' failurePhaseToken: failurePhaseToken,' +
  ' failurePhaseLabel: failurePhaseLabel,' +
  ' failureReportText: failureReportText' +
  ' };';
vm.runInNewContext(script, context);
const api = context.__failureApi;

test('unverified forget outcomes never claim remote removal', () => {
  const start = source.indexOf('    function updatePairUI() {');
  const end = source.indexOf('    // Show the automatic stop message', start);
  assert.ok(start > 0 && end > start, 'pairing presentation must exist');
  for (const outcome of ['confirmed', 'not_delivered']) {
    const dom = Object.fromEntries([
      'pairPill', 'pairPillText', 'pairStatus', 'pairCodeBlock', 'pairCode',
      'pairStart', 'pairCancel', 'pairForget', 'phoneProbe'
    ].map((name) => [name, {}]));
    const scope = {
      state: { pair: { state: 'idle' }, forget: { state: outcome } },
      dom,
      PAIR_ACTIVE: {},
      setText: (node, text) => { node.textContent = text; }
    };
    vm.runInNewContext(source.slice(start, end) + '\nupdatePairUI();', scope);
    assert.equal(dom.pairPillText.textContent, 'Forget not confirmed');
    assert.match(dom.pairStatus.textContent, /Could not confirm/);
    assert.match(dom.pairStatus.textContent, /may still trust/);
  }
});

test('a known phase has a plain label and a report word', () => {
  assert.equal(api.failurePhaseToken('connect'), 'connect');
  assert.equal(api.failurePhaseToken('GREETING'), 'greeting');
  assert.equal(api.failurePhaseToken(' auth '), 'auth');
  assert.equal(api.failurePhaseToken('request'), 'request');
  assert.equal(api.failurePhaseLabel('connect'), 'Source connection');
  assert.equal(api.failurePhaseLabel('greeting'), 'Greeting');
  assert.equal(api.failurePhaseLabel('auth'), 'Sign-in');
  assert.equal(api.failurePhaseLabel('request'), 'Destination request');
});

test('a missing or unknown phase is tolerated', () => {
  for (const value of [undefined, null, '', '   ', 7, {}]) {
    assert.equal(api.failurePhaseToken(value), null, String(value));
    assert.equal(api.failurePhaseLabel(value), '', String(value));
  }
  assert.equal(api.failurePhaseToken('quantum'), 'unknown');
  assert.equal(api.failurePhaseLabel('quantum'), 'Unknown stage');
});

test('the copied report keeps groups apart by phase', () => {
  const data = {
    token: 'secret',
    groups: [
      {
        proto: 'tcp', family: 'ipv4', port: 443, reason: 'other', phase: 'request',
        count: 2, name: 'example.com', example_ip: '203.0.113.5'
      },
      {
        proto: 'tcp', family: 'ipv4', port: 443, reason: 'other', phase: 'connect',
        count: 2, name: 'example.com', example_ip: '203.0.113.5'
      },
      {
        proto: 'tcp', family: 'ipv4', port: 443, reason: 'other', phase: null,
        count: 1, name: 'example.com', example_ip: '203.0.113.5'
      },
      {
        proto: 'tcp', family: 'ipv4', port: 443, reason: 'other', phase: 'quantum',
        count: 1, name: 'example.com', example_ip: '203.0.113.5'
      }
    ]
  };
  assert.equal(api.failureReportText(data), [
    '2x web ipv4 443 other request example.com 203.0.113.5',
    '2x web ipv4 443 other connect example.com 203.0.113.5',
    '1x web ipv4 443 other - example.com 203.0.113.5',
    '1x web ipv4 443 other unknown example.com 203.0.113.5'
  ].join('\n'));
  assert.ok(!api.failureReportText(data).includes('secret'));
  assert.equal(api.failureReportText(null), '');
  assert.equal(api.failureReportText({}), '');
});
