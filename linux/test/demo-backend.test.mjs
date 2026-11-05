import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createDemoBackend, BackendError } = require('../src/backend/demo-backend.js');

function backendAt(start = 1000000) {
  const clock = { now: start };
  const backend = createDemoBackend({
    now: () => clock.now,
    codeGenerator: () => '482931',
    appVersion: '0.1.0',
    platform: 'linux',
    arch: 'x64'
  });
  return { backend, clock };
}

function pairedBackend() {
  const value = backendAt();
  value.backend.beginPairing();
  value.clock.now += 701;
  value.backend.pairState();
  value.clock.now += 3001;
  value.backend.pairState();
  return value;
}

function runningBackend() {
  const value = pairedBackend();
  value.backend.start({ ping: true });
  value.clock.now += 901;
  value.backend.status();
  return value;
}

test('the demo starts unpaired and clearly labeled', () => {
  const { backend } = backendAt();
  const status = backend.status();
  assert.equal(backend.mode, 'demo');
  assert.equal(status.demo, true);
  assert.equal(status.running, false);
  assert.equal(status.mode, null);
  assert.equal(status.paired, false);
  assert.equal(status.phone.state, 'unpaired');
  assert.equal(status.engine.boundary, 'not_connected');
  assert.equal(status.engine.tunnel, 'not_implemented');
  assert.equal(status.platform.os, 'linux');
  assert.equal(status.forget.state, 'none');
  assert.ok(status.phone.checked_at > 0);
});

test('the demo pairing advances by the injected clock', () => {
  const { backend, clock } = backendAt();
  const start = backend.beginPairing();
  assert.equal(start.state, 'connecting');
  clock.now += 699;
  assert.equal(backend.pairState().state, 'connecting');
  clock.now += 1;
  const confirm = backend.pairState();
  assert.equal(confirm.state, 'confirm');
  assert.equal(confirm.code, '482931');
  clock.now += 3000;
  assert.equal(backend.pairState().state, 'paired');
  const status = backend.status();
  assert.equal(status.paired, true);
  assert.equal(status.phone.state, 'ready');
  assert.equal(status.phone.trusted_by_source, true);
});

test('a canceled pairing returns to idle', () => {
  const { backend, clock } = backendAt();
  backend.beginPairing();
  clock.now += 701;
  assert.equal(backend.pairState().state, 'confirm');
  assert.equal(backend.cancelPairing().state, 'idle');
  assert.equal(backend.status().paired, false);
});

test('the demo start and stop use a bounded operation window', () => {
  const { backend, clock } = pairedBackend();
  const started = backend.start({ ping: true });
  assert.equal(started.running, false);
  clock.now += 899;
  assert.equal(backend.status().running, false);
  clock.now += 1;
  const status = backend.status();
  assert.equal(status.running, true);
  assert.equal(status.mode, 'phone');
  assert.equal(status.icmp_enabled, true);
  assert.equal(status.phone.connections, 2);

  const stopping = backend.stop();
  assert.equal(stopping.running, true);
  clock.now += 600;
  const stopped = backend.status();
  assert.equal(stopped.running, false);
  assert.equal(stopped.mode, null);
  assert.equal(stopped.icmp_enabled, false);
  assert.equal(stopped.last_stop.reason, 'user');
  assert.equal(stopped.last_stop_message, 'You turned the tunnel off.');
});

test('the start refuses an unpaired source device', () => {
  const { backend } = backendAt();
  assert.throws(() => backend.start({ ping: true }), (error) => {
    assert.equal(error instanceof BackendError, true);
    assert.equal(error.code, 'not_ready');
    return true;
  });
});

test('the demo seeds a bounded failure record after the first start', () => {
  const { backend } = runningBackend();
  const failures = backend.failures();
  assert.equal(failures.demo, true);
  assert.equal(failures.groups.length, 4);
  assert.equal(failures.total, 6);
  assert.equal(failures.recent.length, 4);
  assert.equal(failures.groups[0].example_ip, '192.0.2.10');
  assert.equal(failures.groups[3].example_ip, '2001:db8::20');
  assert.equal(failures.groups[0].phase, 'request');
  assert.equal(failures.groups[1].phase, 'connect');
  assert.equal(failures.groups[1].name, 'example.com');
  assert.equal(failures.groups[2].phase, 'greeting');
  assert.equal(failures.groups[3].phase, null);
  assert.equal(failures.recent[0].phase, 'request');
  assert.equal(failures.recent[1].phase, 'connect');
  assert.equal(failures.recent[3].phase, null);
});

test('Forget is blocked while running, then completes after a stop', () => {
  const { backend, clock } = runningBackend();
  assert.throws(() => backend.forget(), (error) => {
    assert.equal(error.code, 'forget_blocked');
    assert.equal(error.status, 409);
    return true;
  });

  backend.stop();
  clock.now += 601;
  backend.status();
  const pending = backend.forget();
  assert.equal(pending.state, 'pending');
  clock.now += 500;
  const status = backend.status();
  assert.equal(status.forget.state, 'confirmed');
  assert.equal(status.forget.attempts, 1);
  assert.equal(status.paired, false);
  assert.equal(status.phone.state, 'unpaired');
});

test('the probe is rate limited and refreshes the check time', () => {
  const { backend, clock } = pairedBackend();
  const first = backend.probe();
  assert.ok(first.phone.checked_at > 0);
  assert.throws(() => backend.probe(), (error) => {
    assert.equal(error.code, 'rate_limited');
    assert.equal(error.status, 429);
    return true;
  });
  clock.now += 501;
  assert.doesNotThrow(() => backend.probe());
});

test('the demo scenarios set only simulated state', () => {
  const { backend } = pairedBackend();

  const stopped = backend.applyScenario('source-stopped');
  assert.equal(stopped.running, true);
  assert.equal(stopped.mode, 'phone');
  assert.equal(stopped.phone.state, 'not_responding');

  const notTrusted = backend.applyScenario('not-trusted');
  assert.equal(notTrusted.running, false);
  assert.equal(notTrusted.paired, true);
  assert.equal(notTrusted.phone.state, 'not_trusted');
  assert.equal(notTrusted.phone.trusted_by_source, false);

  const ready = backend.applyScenario('ready');
  assert.equal(ready.paired, true);
  assert.equal(ready.phone.state, 'ready');

  const reset = backend.applyScenario('reset');
  assert.equal(reset.paired, false);
  assert.equal(reset.running, false);
  assert.equal(backend.failures().groups.length, 0);
  assert.throws(() => backend.applyScenario('open-a-tunnel'), (error) => {
    assert.equal(error.code, 'invalid_scenario');
    return true;
  });
});

test('a running demo refuses pairing without changing state', () => {
  const { backend } = runningBackend();
  assert.throws(() => backend.beginPairing(), (error) => {
    assert.equal(error.code, 'tunnel_running');
    return true;
  });
  assert.equal(backend.status().running, true);
});

test('stop is idempotent', () => {
  const { backend } = pairedBackend();
  assert.doesNotThrow(() => backend.stop());
  assert.equal(backend.status().running, false);
});

test('activity is bounded, ordered, and reads from a sequence', () => {
  const { backend } = backendAt();
  const first = backend.activity({ since: 0 });
  assert.equal(first.logs.length, 1);
  assert.equal(first.next, 1);
  assert.equal(backend.activity({ since: first.next }).logs.length, 0);

  backend.beginPairing();
  const second = backend.activity({ since: first.next });
  assert.ok(second.logs.length >= 1);
  assert.ok(second.next > first.next);
  for (const entry of second.logs) {
    assert.equal(typeof entry.seq, 'number');
    assert.equal(typeof entry.ts, 'number');
    assert.equal(typeof entry.msg, 'string');
  }
});

test('returned status and failure values are copies', () => {
  const { backend } = runningBackend();
  const status = backend.status();
  status.phone.state = 'not_trusted';
  assert.equal(backend.status().phone.state, 'ready');

  const failures = backend.failures();
  failures.groups[0].count = 99;
  assert.equal(backend.failures().groups[0].count, 2);
});

test('diagnostics are simulated and carry the boundary state', () => {
  const { backend } = runningBackend();
  const report = backend.diagnostics();
  assert.equal(report.demo, true);
  assert.equal(report.engine.boundary, 'not_connected');
  assert.equal(report.engine.tunnel, 'not_implemented');
  assert.equal(report.running, true);
  assert.ok(report.setup.connect_ms.count >= 1);
  assert.equal(report.failures.total, 6);
});
