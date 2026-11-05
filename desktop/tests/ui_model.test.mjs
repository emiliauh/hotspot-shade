import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const model = require('../ui/model.js');

function status(overrides = {}) {
  return {
    demo: true,
    running: false,
    mode: null,
    paired: false,
    icmp_enabled: false,
    phone: {
      state: 'unpaired',
      message: 'Not paired. Open HotspotShade on your source device, then pair.',
      checked_at: 100,
      connections: null,
      trusted_by_source: null,
      port_changed: false
    },
    forget: { state: 'none', attempts: 0 },
    last_stop: { reason: null, at: null },
    last_stop_message: null,
    ...overrides
  };
}

function derive(overrides = {}) {
  return model.deriveDashboard({
    status: status(),
    hasStatus: true,
    pair: { state: 'idle' },
    freshness: 'fresh',
    busy: null,
    error: null,
    forgetBlocked: false,
    nowSeconds: 110,
    ...overrides
  });
}

test('a loaded status returns a complete dashboard view', () => {
  const view = derive();
  assert.ok(view, 'deriveDashboard must return a view');
  for (const key of ['kind', 'title', 'subtitle', 'source', 'connection', 'attention']) {
    assert.ok(key in view, 'missing ' + key);
  }
});

test('an unpaired demo offers Pair', () => {
  const view = derive();
  assert.equal(view.title, 'Not paired');
  assert.equal(view.primary.id, 'pair');
  assert.equal(view.kind, 'off');
  assert.equal(view.demo, true);
  assert.equal(view.source.value, 'Not paired');
});

test('a paired and ready source device offers Turn on', () => {
  const view = derive({
    status: status({
      paired: true,
      phone: { state: 'ready', message: 'The source device is ready.', checked_at: 100, connections: null }
    })
  });
  assert.equal(view.title, 'Ready');
  assert.equal(view.primary.id, 'turnOn');
  assert.equal(view.secondary.id, 'forget');
  assert.equal(view.source.value, 'Paired');
});

test('a running phone tunnel shows ping and connections', () => {
  const view = derive({
    status: status({
      running: true,
      mode: 'phone',
      paired: true,
      icmp_enabled: true,
      phone: { state: 'connected', message: 'Connected to the source device.', checked_at: 100, connections: 2 }
    })
  });
  assert.equal(view.title, 'On');
  assert.equal(view.primary.id, 'turnOff');
  assert.equal(view.connection.value, 'Tunnel on');
  assert.ok(view.connection.details.includes('Ping is on.'));
  assert.ok(view.connection.details.includes('The source device reports 2 active connections.'));
});

test('a proxy-off state waits without a start action', () => {
  const view = derive({
    status: status({
      paired: true,
      phone: { state: 'proxy_off', message: 'Start the proxy on your source device.', checked_at: 100 }
    })
  });
  assert.equal(view.title, 'Paired');
  assert.equal(view.primary, null);
  assert.equal(view.secondary.id, 'forget');
});

test('a not-trusted source device asks for a new pairing', () => {
  const view = derive({
    status: status({
      paired: true,
      phone: { state: 'not_trusted', message: 'The source device does not know this target device. Pair again.', checked_at: 100 }
    })
  });
  assert.equal(view.title, 'Not trusted');
  assert.equal(view.primary.id, 'pairAgain');
  assert.equal(view.kind, 'attention');
});

test('a not-trusted source device during a run keeps the stop action', () => {
  const view = derive({
    status: status({
      running: true,
      mode: 'phone',
      paired: true,
      phone: { state: 'not_trusted', message: 'The source device forgot this target device.', checked_at: 100 }
    })
  });
  assert.equal(view.primary.id, 'turnOff');
  assert.ok(view.attention.includes(model.NOT_TRUSTED_RUNNING));
});

test('an unavailable status never claims the tunnel is on', () => {
  const view = derive({
    status: status({ running: true, paired: true, mode: 'phone' }),
    freshness: 'unavailable'
  });
  assert.equal(view.title, 'Status unavailable');
  assert.equal(view.primary.id, 'checkNow');
  assert.equal(view.source.value, 'The status is unavailable.');
  assert.equal(view.connection.value, 'The status is unavailable.');
});

test('a stale status adds a plain warning and a check action', () => {
  const view = derive({
    status: status({ paired: true, phone: { state: 'proxy_off', message: 'Start the proxy on your source device.' } }),
    freshness: 'stale'
  });
  assert.ok(view.attention.includes(model.STALE_TEXT));
  assert.equal(view.secondary.id, 'checkNow');
});

test('an action error offers Try again', () => {
  const view = derive({ error: 'The demo could not start.' });
  assert.equal(view.title, 'Needs attention');
  assert.equal(view.subtitle, 'The demo could not start.');
  assert.equal(view.primary.id, 'retry');
});

test('a startup failure is not left on the loading screen', () => {
  const view = model.deriveDashboard({
    status: null,
    hasStatus: false,
    error: 'Cannot reach the demo backend.',
    freshness: 'fresh'
  });
  assert.equal(view.title, 'Needs attention');
  assert.equal(view.primary.id, 'retry');
});

test('pairing hides the dashboard actions', () => {
  const view = derive({ pair: { state: 'confirm' } });
  assert.equal(view.title, 'Pairing');
  assert.equal(view.kind, 'pairing');
  assert.equal(view.primary, null);
});

test('a forget result is shown in plain text', () => {
  const view = derive({ status: status({ forget: { state: 'confirmed', attempts: 1 } }) });
  assert.ok(view.subtitle.includes('Forgotten.'));
});

test('the demo label comes from the bridge status', () => {
  assert.equal(derive().demo, true);
  assert.equal(derive({ status: status({ demo: false }) }).demo, false);
});

test('checked text becomes older in plain steps', () => {
  assert.equal(model.checkedText(100, 102), 'Checked just now');
  assert.equal(model.checkedText(100, 109), 'Checked just now');
  assert.equal(model.checkedText(100, 110), 'Checked 10 seconds ago');
  assert.equal(model.checkedText(100, 190), 'Checked 1 minute ago');
  assert.equal(model.checkedText(null, 190), null);
  assert.equal(model.checkedText(-1e100, 190), null);
  assert.equal(model.checkedText(-Number.MAX_VALUE, Number.MAX_VALUE), null);
});

test('format helpers keep demo counters readable', () => {
  assert.equal(model.formatInt(999), '999');
  assert.equal(model.formatInt(1500), '1.5k');
  assert.equal(model.formatBytes(1536), '1.5 KB');
  assert.equal(model.formatDuration(65), '1m 5s');
  assert.match(model.formatClock(0), /^\d\d:\d\d:\d\d$/);
  assert.equal(model.formatClock(null), 'n/a');
});

test('the pairing view holds the fixed demo code', () => {
  const view = model.pairingView({ state: 'confirm', code: '123 456' }, null);
  assert.equal(view.active, true);
  assert.equal(view.code, '123 456');
  assert.equal(view.message, 'Check that both screens show the same code.');
  assert.equal(model.pairingView({ state: 'idle' }, null).active, false);
});

test('failure stages decode to fixed labels and tolerate missing values', () => {
  assert.equal(model.failurePhase(' AUTH '), 'auth');
  assert.equal(model.failurePhase('future'), 'unknown');
  assert.equal(model.failurePhase(null), null);
  assert.equal(model.failurePhase(42), null);
  assert.equal(model.failurePhaseLabel('connect'), 'Source connection');
  assert.equal(model.failurePhaseLabel('greeting'), 'Greeting');
  assert.equal(model.failurePhaseLabel('auth'), 'Sign-in');
  assert.equal(model.failurePhaseLabel('request'), 'Destination request');
  assert.equal(model.failurePhaseLabel('future'), 'Unknown stage');
  assert.equal(model.failurePhaseLabel(undefined), 'Not reported');
  assert.equal(model.failurePhaseWord('future'), 'unknown');
  assert.equal(model.failurePhaseWord(null), '-');
  assert.equal(model.failureReason('timed_out').table, 'No answer in time');
  assert.equal(model.failureReason('timed_out').phrase, 'got no answer in time');
});

test('one destination and reason stays separate for different stages', () => {
  const failures = {
    demo: true,
    total: 4,
    dropped: 0,
    groups: [
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'timed_out', phase: 'request', count: 2, name: 'example.com', example_ip: '203.0.113.5' },
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'timed_out', phase: 'connect', count: 2, name: 'example.com', example_ip: '203.0.113.5' }
    ]
  };
  const rows = model.failureRows(failures);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].target, 'example.com');
  assert.equal(rows[1].target, 'example.com');
  assert.equal(rows[0].reason, 'No answer in time');
  assert.equal(rows[1].reason, 'No answer in time');
  assert.deepEqual(rows.map((row) => row.phase), ['Source connection', 'Destination request']);
  assert.notEqual(rows[0].id, rows[1].id);
  assert.match(rows[1].summary, /got no answer in time while the source device checked the destination$/);

  const report = model.failureReport(failures);
  assert.match(report, /^HotspotShade simulated failure report/);
  assert.match(report, /^Data: simulated by DemoBackend$/m);
  assert.match(report, /2x web ipv4 443 timed_out connect example\.com 203\.0\.113\.5/);
  assert.match(report, /2x web ipv4 443 timed_out request example\.com 203\.0\.113\.5/);
  assert.equal(report.split('\n').filter((line) => line.includes('example.com')).length, 2);
});

test('missing and unknown stages keep a safe display and copy word', () => {
  const failures = {
    demo: true,
    total: 3,
    dropped: 0,
    groups: [
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'refused', count: 1, name: 'missing.example' },
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'refused', phase: 'future', count: 1, name: 'future.example' },
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'refused', phase: 7, count: 1, name: 'numeric.example' }
    ]
  };
  const rows = model.failureRows(failures);
  assert.equal(rows.length, 3);
  const missing = rows.find((row) => row.target === 'missing.example');
  const future = rows.find((row) => row.target === 'future.example');
  const numeric = rows.find((row) => row.target === 'numeric.example');
  assert.equal(missing.phase, 'Not reported');
  assert.equal(missing.phaseWord, '-');
  assert.equal(future.phase, 'Unknown stage');
  assert.equal(future.phaseWord, 'unknown');
  assert.equal(numeric.phase, 'Not reported');
  const report = model.failureReport(failures);
  assert.match(report, /refused - missing\.example/);
  assert.match(report, /refused unknown future\.example/);
  assert.match(report, /refused - numeric\.example/);
});
