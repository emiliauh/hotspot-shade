import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const model = require('../src/renderer/model.js');

function status(overrides = {}) {
  return {
    demo: true,
    running: false,
    mode: null,
    paired: false,
    icmp_enabled: false,
    platform: { os: 'linux', arch: 'x64' },
    phone: {
      state: 'unpaired',
      message: 'Pair with your source device to use it.',
      checked_at: 100,
      connections: null,
      trusted_by_source: null,
      port_changed: false
    },
    forget: { state: 'none', attempts: 0 },
    last_stop: { reason: null, at: null },
    last_stop_message: null,
    engine: { version: '0.1.0', boundary: 'not_connected', tunnel: 'not_implemented' },
    uptime_s: 10,
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

test('a pairing code is shown in groups of three digits', () => {
  assert.equal(model.groupPairingCode('482931'), '482 931');
  assert.equal(model.groupPairingCode('48-29 31'), '482 931');
  assert.equal(model.groupPairingCode(null), '');
});

test('the checked time uses short plain words', () => {
  assert.equal(model.checkedText(110, 111), 'Checked just now');
  assert.equal(model.checkedText(100, 109), 'Checked just now');
  assert.equal(model.checkedText(100, 110), 'Checked 10 seconds ago');
  assert.equal(model.checkedText(100, 111), 'Checked 11 seconds ago');
  assert.equal(model.checkedText(100, 171), 'Checked 1 minute ago');
  assert.equal(model.checkedText(null, 171), null);
  assert.equal(model.checkedText(-1e100, 171), null);
  assert.equal(model.checkedText(-Number.MAX_VALUE, Number.MAX_VALUE), null);
});

test('the freshness window is fresh, stale, then unavailable', () => {
  assert.equal(model.statusFreshness(null, 1000, true), 'fresh');
  assert.equal(model.statusFreshness(1000, 2999, true), 'fresh');
  assert.equal(model.statusFreshness(1000, 4000, true), 'stale');
  assert.equal(model.statusFreshness(1000, 11000, true), 'unavailable');
});

test('the first status is a loading state, not a tunnel claim', () => {
  const view = derive({ status: null, hasStatus: false });
  assert.equal(view.title, 'Starting HotspotShade');
  assert.equal(view.kind, 'busy');
  assert.equal(view.primary, null);
  assert.equal(view.source.value, 'Loading');
  assert.equal(view.connection.value, 'Loading');
});

test('a bridge error shows Needs attention and a retry action', () => {
  const view = derive({ status: null, hasStatus: false, error: 'The demo bridge is unavailable.' });
  assert.equal(view.title, 'Needs attention');
  assert.equal(view.subtitle, 'The demo bridge is unavailable.');
  assert.equal(view.primary.id, 'retry');
  assert.equal(view.kind, 'attention');
});

test('an unpaired demo offers Pair and stays off', () => {
  const view = derive();
  assert.equal(view.title, 'Not paired');
  assert.equal(view.kind, 'off');
  assert.equal(view.primary.id, 'pair');
  assert.equal(view.secondary, null);
  assert.equal(view.source.value, 'Not paired');
  assert.deepEqual(view.source.details, ['Pair when you are ready.']);
  assert.equal(view.connection.value, 'Tunnel off');
  assert.deepEqual(view.connection.details, ['No connection yet.']);
  assert.equal(view.demo, true);
});

test('recovery offers a stop attempt only with a fresh running indication', () => {
  for (const recovery of [{ state: 'unknown' }, { cleanup_blocked: true }]) {
    const fresh = derive({ status: status({ ...recovery, running: true }) });
    assert.equal(fresh.primary.id, 'checkNow');
    assert.equal(fresh.secondary.id, 'turnOff');
    assert.equal(fresh.secondary.label, 'Try to turn off');
    for (const running of [false, undefined]) {
      const view = derive({ status: status({ ...recovery, running }) });
      assert.equal(view.secondary, null);
    }
    const stale = derive({ status: status({ ...recovery, running: true }), freshness: 'stale' });
    assert.equal(stale.secondary, null);
  }
});

test('a failed recovery stop remains visible', () => {
  const view = derive({
    status: status({ running: true, state: 'unknown' }),
    error: 'The tunnel may still need cleanup.',
    retryAction: 'stop'
  });
  assert.ok(view.attention.includes('The tunnel may still need cleanup.'));
  assert.equal(view.secondary.id, 'turnOff');
});

test('a paired source device offers Turn on and Forget', () => {
  const view = derive({
    status: status({
      paired: true,
      phone: {
        state: 'ready',
        message: 'The source device is ready.',
        checked_at: 100,
        connections: null,
        trusted_by_source: true
      }
    })
  });
  assert.equal(view.title, 'Ready');
  assert.equal(view.kind, 'off');
  assert.equal(view.primary.id, 'turnOn');
  assert.equal(view.secondary.id, 'forget');
  assert.equal(view.source.value, 'Paired');
  assert.deepEqual(view.source.details, ['The pairing is saved.']);
});

test('a running demo shows ping, connections, and Turn off', () => {
  const view = derive({
    status: status({
      running: true,
      mode: 'phone',
      paired: true,
      icmp_enabled: true,
      phone: {
        state: 'ready',
        message: 'The source device is ready.',
        checked_at: 100,
        connections: 3,
        trusted_by_source: true
      }
    })
  });
  assert.equal(view.title, 'On');
  assert.equal(view.kind, 'on');
  assert.equal(view.primary.id, 'turnOff');
  assert.equal(view.secondary, null);
  assert.equal(view.connection.value, 'Tunnel on');
  assert.ok(view.connection.details.includes('Ping is on.'));
  assert.ok(view.connection.details.includes('The source device reports 3 active connections.'));
});

test('a source device that stopped answering adds an attention line', () => {
  const view = derive({
    status: status({
      running: true,
      mode: 'phone',
      paired: true,
      icmp_enabled: false,
      phone: {
        state: 'not_responding',
        message: 'The source device stopped answering.',
        checked_at: 100,
        connections: 0,
        trusted_by_source: true
      }
    })
  });
  assert.equal(view.title, 'On');
  assert.equal(view.kind, 'on');
  assert.ok(view.attention.includes('The source device stopped answering. New connections fail.'));
});

test('a not trusted source device is an attention state with Pair again', () => {
  const view = derive({
    status: status({
      paired: true,
      phone: {
        state: 'not_trusted',
        message: 'The source device does not know this target device.',
        checked_at: 100,
        connections: null,
        trusted_by_source: false
      }
    })
  });
  assert.equal(view.title, 'Not trusted');
  assert.equal(view.kind, 'attention');
  assert.equal(view.primary.id, 'pairAgain');
  assert.equal(view.source.value, 'Not trusted');
  assert.deepEqual(view.source.details, ['Pair again to restore trust.']);
});

test('waiting for the source device has no turn on action', () => {
  for (const state of ['no_hotspot', 'not_running']) {
    const view = derive({
      status: status({
        paired: true,
        phone: { state, message: '', checked_at: 100, connections: null, trusted_by_source: true }
      })
    });
    assert.equal(view.title, 'Waiting for your source device');
    assert.equal(view.primary, null);
    assert.equal(view.source.value, 'Paired');
    assert.deepEqual(view.source.details, ['The app checks for the source device every second.']);
  }
});

test('a stale status adds a warning and a Check now action', () => {
  const view = derive({ freshness: 'stale' });
  assert.equal(view.stale, true);
  assert.ok(view.attention.includes('The engine did not answer. This status may be out of date.'));
  assert.equal(view.secondary.id, 'checkNow');
});

test('an unavailable status does not claim a tunnel state', () => {
  const view = derive({
    freshness: 'unavailable',
    status: status({ running: true, paired: true })
  });
  assert.equal(view.title, 'Status unavailable');
  assert.equal(view.unavailable, true);
  assert.equal(view.primary.id, 'checkNow');
  assert.equal(view.source.value, 'The status is unavailable.');
  assert.equal(view.connection.value, 'The status is unavailable.');
  assert.ok(view.attention.includes('The engine did not answer. This status may be out of date.'));
});

test('an unknown service state does not claim the tunnel is on', () => {
  const message = 'The service state is unavailable after an interrupted operation.';
  const view = derive({
    status: status({ running: true, paired: true, state: 'unknown', error: message,
      phone: { state: 'not_responding', port_changed: true } }),
    tokenRejected: 'old pairing error',
    forgetBlocked: true
  });
  assert.equal(view.title, 'Status unavailable');
  assert.equal(view.subtitle, message);
  assert.equal(view.unavailable, true);
  assert.equal(view.primary.id, 'checkNow');
  assert.equal(view.secondary.id, 'turnOff');
  assert.equal(view.secondary.label, 'Try to turn off');
  assert.equal(view.modeLocked, true);
  assert.equal(view.connection.value, 'The status is unavailable.');
  assert.ok(!view.attention.includes('The source device stopped answering.'));
  assert.ok(!view.attention.includes('Turn off the tunnel to forget this source device.'));
});

test('an unpaired status without source details stays consistent', () => {
  const view = derive({ status: { running: false, paired: false } });
  assert.notEqual(view.title, 'Status unavailable');
  assert.equal(view.unavailable, false);
  assert.equal(view.source.value, 'Not paired');
});

test('a paired status without source details offers a fresh check', () => {
  const view = derive({ status: { running: false, paired: true } });
  assert.equal(view.title, 'Status unavailable');
  assert.equal(view.primary.id, 'checkNow');
  assert.equal(view.source.value, 'Paired');
  assert.notEqual(view.primary.id, 'turnOn');
});

test('missing pairing evidence is not reported as unpaired', () => {
  for (const paired of [undefined, null, 'false']) {
    const view = derive({ status: { running: false, paired } });
    assert.equal(view.pairingKnown, false);
    assert.equal(view.title, 'Status unavailable');
    assert.equal(view.primary.id, 'checkNow');
    assert.equal(view.source.value, 'The status is unavailable.');
    assert.notEqual(view.primary.id, 'pair');
  }
});

test('an incomplete running status cannot enable a start or claim stopped', () => {
  for (const running of [undefined, null, 'false']) {
    for (const startMode of ['phone', 'direct']) {
      const view = derive({ status: { running, paired: true }, startMode });
      assert.equal(view.unavailable, true);
      assert.equal(view.primary.id, 'checkNow');
      assert.equal(view.connection.value, 'The status is unavailable.');
      assert.equal(view.modeLocked, true);
    }
  }
});

test('start and stop confirmation require explicit state without recovery uncertainty', () => {
  for (const running of [false, true]) {
    assert.equal(model.tunnelStateConfirmed({ running }, running), true);
    assert.equal(model.tunnelStateConfirmed({ running: !running }, running), false);
    assert.equal(model.tunnelStateConfirmed({ running, state: 'unknown' }, running), false);
    assert.equal(model.tunnelStateConfirmed({ running, cleanup_blocked: true }, running), false);
    assert.equal(model.tunnelStateConfirmed({}, running), false);
    assert.equal(model.tunnelStateConfirmed({ running: String(running) }, running), false);
  }
});

test('a cleanup-blocked stopped status does not offer restart or Forget', () => {
  const view = derive({
    status: status({ running: false, paired: true, cleanup_blocked: true }),
    forgetBlocked: true
  });
  assert.equal(view.unavailable, true);
  assert.match(view.subtitle, /cleanup did not finish/i);
  assert.equal(view.primary.id, 'checkNow');
  assert.equal(view.secondary, null);
  assert.equal(view.modeLocked, true);
});

test('direct mode does not depend on missing pairing evidence', () => {
  const view = derive({ status: { running: false }, startMode: 'direct' });
  assert.equal(view.pairingKnown, false);
  assert.equal(view.primary.id, 'turnOn');
  assert.equal(view.source.value, 'Not used');
});

test('Forget is blocked while the tunnel runs', () => {
  const view = derive({
    forgetBlocked: true,
    status: status({
      running: true,
      mode: 'phone',
      paired: true,
      icmp_enabled: true,
      phone: { state: 'ready', message: '', checked_at: 100, connections: 2, trusted_by_source: true }
    })
  });
  assert.equal(view.attention[0], 'Turn off the tunnel to forget this source device.');
  assert.equal(view.secondary.id, 'turnOffAndForget');
});

test('an action error shows Needs attention and a retry action', () => {
  const view = derive({ error: 'The simulated source device is not ready.' });
  assert.equal(view.title, 'Needs attention');
  assert.equal(view.subtitle, 'The simulated source device is not ready.');
  assert.equal(view.primary.id, 'retry');
  assert.equal(view.kind, 'attention');
});

test('an action error keeps the stop action available for a running tunnel', () => {
  for (const mode of ['tun', 'phone']) {
    const view = derive({
      status: status({ running: true, paired: true, mode }),
      error: 'The previous start did not finish.'
    });
    assert.equal(view.title, 'Needs attention');
    assert.equal(view.primary.id, 'turnOff');
    assert.equal(view.subtitle, 'The previous start did not finish.');
  }
});

test('a pairing state replaces the dashboard card actions', () => {
  const view = derive({ pair: { state: 'confirm', code: '482931' } });
  assert.equal(view.title, 'Pairing');
  assert.equal(view.kind, 'pairing');
  assert.equal(view.primary, null);
  assert.equal(view.secondary, null);
});

test('a forget message wins over the usual unpaired hint', () => {
  const view = derive({
    status: status({ forget: { state: 'confirmed', attempts: 1 } })
  });
  assert.equal(view.title, 'Not paired');
  assert.equal(view.subtitle, 'Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it.');
  assert.equal(view.primary.id, 'pair');
});

test('an unconfirmed forget does not claim the source failed to answer', () => {
  const view = derive({
    status: status({ forget: { state: 'not_delivered', attempts: 3 } })
  });
  assert.equal(view.subtitle, 'Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it.');
});

test('the pairing view carries the code and the plain phase text', () => {
  const connecting = model.pairingView({ state: 'connecting' });
  assert.equal(connecting.active, true);
  assert.equal(connecting.message, 'Connecting to your source device.');

  const confirm = model.pairingView({ state: 'confirm', code: '482931' });
  assert.equal(confirm.active, true);
  assert.equal(confirm.code, '482 931');
  assert.equal(confirm.message, 'Check that both screens show the same code.');

  const paired = model.pairingView({ state: 'paired' });
  assert.equal(paired.active, false);
  assert.equal(paired.message, 'The pairing is saved.');

  const failed = model.pairingView({ state: 'failed', error: 'The code did not match.' });
  assert.equal(failed.message, 'The code did not match.');
});

test('failure rows sort by count and use plain words', () => {
  const failures = {
    since: 100,
    total: 6,
    dropped: 0,
    demo: true,
    groups: [
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'timed_out', phase: 'request', count: 3, name: 'example.com', example_ip: '192.0.2.10' },
      { proto: 'dns', family: 'ipv4', port: 53, reason: 'unreachable', phase: 'greeting', count: 2, name: 'dns.example', example_ip: '192.0.2.53' },
      { proto: 'tcp', family: 'ipv6', port: 80, reason: 'refused', phase: null, count: 1, name: null, example_ip: '2001:db8::20' }
    ]
  };
  const view = model.failureView(failures);
  assert.equal(view.state, 'ready');
  assert.equal(view.copyable, true);
  assert.equal(view.rows.length, 3);
  assert.equal(view.rows[0].count, 3);
  assert.equal(view.rows[0].kind, 'Web');
  assert.equal(view.rows[0].reason, 'No answer in time');
  assert.equal(view.rows[0].phase, 'Destination request');
  assert.equal(view.rows[1].kind, 'DNS');
  assert.equal(view.rows[1].phase, 'Greeting');
  assert.equal(view.rows[2].target, '2001:db8::20');
  assert.equal(view.rows[2].phase, 'Not reported');
  assert.match(view.summary, /^Simulated data\. 6 failed attempts this session\.$/);
  assert.match(view.report, /^HotspotShade simulated failure report/);
  assert.match(view.report, /3x web ipv4 443 timed_out request example\.com 192\.0\.2\.10/);
  assert.match(view.report, /1x web ipv6 80 refused - - 2001:db8::20/);
  assert.equal(model.failureView({ demo: true, groups: [], total: 0, dropped: 0 }).state, 'empty');
  assert.equal(model.failureView(null).state, 'unavailable');
});

test('failure stages decode safely and keep groups apart', () => {
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

  const failures = {
    demo: true,
    total: 6,
    dropped: 0,
    groups: [
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'timed_out', phase: 'request', count: 2, name: 'example.com', example_ip: '192.0.2.10' },
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'timed_out', phase: 'connect', count: 2, name: 'example.com', example_ip: '192.0.2.10' },
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'refused', count: 1, name: 'missing.example' },
      { proto: 'tcp', family: 'ipv4', port: 443, reason: 'refused', phase: 'future', count: 1, name: 'future.example' }
    ]
  };
  const rows = model.failureRows(failures);
  assert.equal(rows.length, 4);
  const sameTarget = rows.filter((row) => row.target === 'example.com');
  assert.equal(sameTarget.length, 2);
  assert.deepEqual(sameTarget.map((row) => row.phase), ['Source connection', 'Destination request']);
  assert.notEqual(sameTarget[0].id, sameTarget[1].id);
  assert.match(sameTarget[1].summary, /got no answer in time while the source device checked the destination$/);
  assert.equal(rows.find((row) => row.target === 'missing.example').phase, 'Not reported');
  assert.equal(rows.find((row) => row.target === 'future.example').phase, 'Unknown stage');

  const report = model.failureReport(failures);
  assert.match(report, /2x web ipv4 443 timed_out connect example\.com 192\.0\.2\.10/);
  assert.match(report, /2x web ipv4 443 timed_out request example\.com 192\.0\.2\.10/);
  assert.match(report, /1x web ipv4 443 refused - missing\.example/);
  assert.match(report, /1x web ipv4 443 refused unknown future\.example/);
});

test('the last stop line uses the engine message only while the tunnel is off', () => {
  assert.equal(
    model.lastStopLine({ running: false, last_stop_message: 'The hotspot turned off, so HotspotShade turned the tunnel off.' }),
    'Last stop: The hotspot turned off, so HotspotShade turned the tunnel off.'
  );
  assert.equal(model.lastStopLine({ running: true, last_stop_message: 'The hotspot turned off.' }), null);
  assert.equal(model.lastStopLine({ running: false, last_stop_message: null }), null);
  assert.equal(model.lastStopLine({ running: false, last_stop_message: 'a\n b' }), 'Last stop: a\nb');
});

test('the diagnostics report is labeled simulated and has no addresses', () => {
  const report = model.diagnosticsReport({
    demo: true,
    running: false,
    engine: { version: '0.1.0', boundary: 'not_connected', tunnel: 'not_implemented', uptime_s: 12, workers: 1 },
    setup: { connect_ms: { count: 1, p50: 4, p95: 12, max: 38 } },
    dns: { lookups: 0, ok: 0, failed: 0, ms: { count: 0, p50: 0, p95: 0, max: 0 } },
    queues: { input: [], output: { peak: 0, max_age_us: 0 } },
    udp: { flows: 0, age_drops: 0 },
    tcp: { flows_peak: 0, retransmits: 0, zero_window_ms: 0 },
    failures: { total: 0, dropped: 0 }
  });
  assert.match(report, /^HotspotShade diagnostics \(simulated demo\)/);
  assert.match(report, /Engine boundary: not_connected/);
  assert.match(report, /Tunnel: not_implemented/);
  assert.doesNotMatch(report, /192\.0\.2/);
  assert.doesNotMatch(report, /token/i);
});

test('activity entries keep a time, a level, and a sequence', () => {
  const entries = model.activityEntries([
    { seq: 1, ts: 1762000000, level: 'warn', msg: 'Hotspot Proxy stopped.' },
    { seq: 2, ts: 1762000001, level: 'error', msg: '' }
  ]);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].level, 'warn');
  assert.equal(entries[0].seq, '1');
  assert.equal(entries[0].message, 'HotspotShade stopped.');
});

test('the menu command allowlist is explicit', () => {
  for (const command of ['dashboard', 'activity', 'settings', 'advanced', 'refresh', 'check-now', 'theme', 'demo-limitations', 'demo-scenarios']) {
    assert.equal(model.menuCommandAllowed(command), true, command);
  }
  assert.equal(model.menuCommandAllowed('quit'), false);
  assert.equal(model.menuCommandAllowed('open-url'), false);
  assert.equal(model.menuCommandAllowed(''), false);
});

test('the mode choice defaults to source device proxy and locks while running', () => {
  const idle = model.modeChoice({});
  assert.equal(idle.selected, 'phone');
  assert.equal(idle.running, false);
  assert.equal(idle.locked, false);
  assert.deepEqual(idle.rows.map((row) => row.id), ['phone', 'direct']);
  assert.equal(idle.rows[0].pressed, true);
  assert.equal(idle.rows[1].pressed, false);
  assert.match(idle.rows[0].detail, /source device/i);
  assert.match(idle.rows[1].detail, /No app on the source device/i);
  assert.match(idle.rows[1].detail, /IPv6 is blocked by default/i);

  const direct = model.modeChoice({ selected: 'direct' });
  assert.equal(direct.selected, 'direct');
  assert.equal(direct.rows[0].pressed, false);
  assert.equal(direct.rows[1].pressed, true);

  const running = model.modeChoice({ selected: 'phone', runningMode: 'direct' });
  assert.equal(running.selected, 'direct');
  assert.equal(running.running, true);
  assert.equal(running.locked, true);
  assert.ok(running.rows.every((row) => row.disabled));

  for (const value of [null, undefined, 'tun', 1, [], {}]) {
    assert.equal(model.modeChoice({ selected: value }).selected, 'phone');
  }
});

test('a running direct tunnel does not use a source device and states the IPv6 policy', () => {
  const view = derive({
    startMode: 'direct',
    status: status({ running: true, mode: 'tun', paired: false })
  });
  assert.equal(view.title, 'On');
  assert.equal(view.kind, 'on');
  assert.equal(view.primary.id, 'turnOff');
  assert.equal(view.activeMode, 'direct');
  assert.equal(view.runningMode, 'direct');
  assert.equal(view.source.value, 'Not used');
  assert.ok(view.source.details.includes('Direct mode does not use a source device app.'));
  assert.equal(view.connection.value, 'Tunnel on');
  assert.ok(view.connection.details.includes('IPv6 is blocked in direct mode.'));
  assert.ok(view.connection.details.includes('The engine reports direct mode. Live route behavior is not verified by this app.'));
  assert.equal(view.attention.includes('The source device stopped answering. New connections fail.'), false);
});

test('direct mode is ready to start without pairing and leaves source mode intact', () => {
  const direct = derive({ startMode: 'direct' });
  assert.equal(direct.title, 'Direct mode');
  assert.equal(direct.kind, 'off');
  assert.equal(direct.primary.id, 'turnOn');
  assert.equal(direct.source.value, 'Not used');
  assert.equal(direct.connection.value, 'Tunnel off');
  assert.ok(direct.connection.details.includes('IPv6 is blocked in direct mode.'));

  const phone = derive({ startMode: 'phone' });
  assert.equal(phone.title, 'Not paired');
  assert.equal(phone.primary.id, 'pair');
  assert.equal(phone.source.value, 'Not paired');
});

test('known start refusals become plain fixed text', () => {
  assert.match(model.startFailureText('admin_required', 'Start HotspotShade as Administrator to use the tunnel.'), /root engine/);
  assert.equal(model.startFailureText('route_setup', 'x'), 'The tunnel could not configure its routes. Cleanup may need attention. Check the current status before trying again.');
  assert.equal(model.startFailureText('tunnel_setup', 'x'), 'The tunnel could not set up its virtual interface. Check the current status and any cleanup warning before trying again.');
  assert.equal(model.startFailureText('start_cancelled', 'x'), 'The start was cancelled. Check the current status and any cleanup warning before trying again.');
  assert.match(model.startFailureText('service_start', 'x'), /hotspot link/);
  assert.match(model.startFailureText('unsupported_mode', 'x'), /does not support the selected tunnel mode/);
  assert.equal(model.startFailureText('engine_error', 'The service could not start.'), 'The service could not start.');
  assert.equal(model.startFailureText('', ''), 'The tunnel did not start.');
});
