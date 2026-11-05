'use strict';

/* In-memory demo backend for the HotspotShade Linux target app.
 *
 * This backend has no tunnel, no route change, no TUN device, no listener, and
 * no network request. It advances all state from an injected clock, so the
 * hermetic tests are deterministic. Every value that it returns is simulated.
 */

const { randomInt } = require('node:crypto');

const { BackendError } = require('./errors');

const SCENARIOS = Object.freeze(['ready', 'source-stopped', 'not-trusted', 'reset']);
const START_DELAY_MS = 900;
const STOP_DELAY_MS = 600;
const PAIR_CONNECT_MS = 700;
const PAIR_CONFIRM_MS = 3000;
const FORGET_DELAY_MS = 500;
const PROBE_INTERVAL_MS = 500;
const MAX_LOGS = 400;

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function createDemoBackend(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const now = typeof settings.now === 'function' ? settings.now : Date.now;
  const codeGenerator = typeof settings.codeGenerator === 'function'
    ? settings.codeGenerator
    : function () { return String(randomInt(0, 1000000)).padStart(6, '0'); };
  const appVersion = typeof settings.appVersion === 'string' ? settings.appVersion : '0.1.0';
  const platform = typeof settings.platform === 'string' ? settings.platform : process.platform;
  const arch = typeof settings.arch === 'string' ? settings.arch : process.arch;

  let state;

  function nowMilliseconds() {
    return now();
  }

  function nowSeconds() {
    return nowMilliseconds() / 1000;
  }

  function log(level, message) {
    state.seq += 1;
    state.logs.push({
      seq: state.seq,
      ts: nowSeconds(),
      level: level,
      msg: message
    });
    if (state.logs.length > MAX_LOGS) {
      state.logs.splice(0, state.logs.length - MAX_LOGS);
    }
  }

  function setPhone(nextState, message) {
    state.phoneState = nextState;
    state.phoneMessage = message;
  }

  function resetState() {
    const checked = nowSeconds();
    state = {
      paired: false,
      running: false,
      mode: null,
      ping: true,
      icmpEnabled: false,
      phoneState: 'unpaired',
      phoneMessage: 'Pair with your source device to use it.',
      checkedAt: checked,
      connections: null,
      trustedBySource: null,
      portChanged: false,
      pairing: {
        state: 'idle',
        code: null,
        error: null,
        confirmAt: 0,
        completeAt: 0
      },
      operation: null,
      forget: {
        state: 'none',
        attempts: 0,
        endsAt: 0
      },
      lastStop: { reason: null, at: null },
      lastStopMessage: null,
      logs: [],
      seq: 0,
      failures: null,
      probeLastAt: 0,
      counts: {
        starts: 0,
        stops: 0,
        pairs: 0,
        forgets: 0,
        probes: 0,
        checks: 0
      },
      startedAt: nowMilliseconds()
    };
  }

  function reset() {
    resetState();
  }

  resetState();
  log('info', 'The simulated demo backend started. No tunnel, routes, or network traffic.');

  function seedFailures() {
    if (state.failures) return;
    const since = Math.round(nowSeconds() - 240);
    state.failures = {
      since: since,
      total: 6,
      dropped: 0,
      demo: true,
      groups: [
        { proto: 'tcp', family: 'ipv4', port: 443, reason: 'timed_out', phase: 'request', count: 2, name: 'example.com', example_ip: '192.0.2.10' },
        { proto: 'tcp', family: 'ipv4', port: 443, reason: 'timed_out', phase: 'connect', count: 1, name: 'example.com', example_ip: '192.0.2.10' },
        { proto: 'dns', family: 'ipv4', port: 53, reason: 'unreachable', phase: 'greeting', count: 2, name: 'dns.example', example_ip: '192.0.2.53' },
        { proto: 'tcp', family: 'ipv6', port: 80, reason: 'refused', phase: null, count: 1, name: null, example_ip: '2001:db8::20' }
      ],
      recent: [
        { ts: since + 30, proto: 'tcp', family: 'ipv4', ip: '192.0.2.10', port: 443, reason: 'timed_out', phase: 'request', name: 'example.com' },
        { ts: since + 60, proto: 'tcp', family: 'ipv4', ip: '192.0.2.10', port: 443, reason: 'timed_out', phase: 'connect', name: 'example.com' },
        { ts: since + 90, proto: 'dns', family: 'ipv4', ip: '192.0.2.53', port: 53, reason: 'unreachable', phase: 'greeting', name: 'dns.example' },
        { ts: since + 150, proto: 'tcp', family: 'ipv6', ip: '2001:db8::20', port: 80, reason: 'refused', phase: null, name: null }
      ]
    };
  }

  function advance() {
    const milliseconds = nowMilliseconds();

    if (state.operation && milliseconds >= state.operation.endsAt) {
      if (state.operation.kind === 'start') {
        state.running = true;
        state.mode = 'phone';
        state.icmpEnabled = state.ping;
        state.connections = 2;
        state.lastStop = { reason: null, at: null };
        state.lastStopMessage = null;
        state.operation = null;
        state.paired = true;
        state.trustedBySource = true;
        setPhone('ready', 'The source device is ready.');
        state.checkedAt = nowSeconds();
        state.pairing.state = 'paired';
        seedFailures();
        log('info', 'The simulated tunnel is on. Ping is ' + (state.icmpEnabled ? 'on' : 'off') + '.');
      } else if (state.operation.kind === 'stop') {
        state.running = false;
        state.mode = null;
        state.icmpEnabled = false;
        state.connections = 0;
        state.operation = null;
        state.lastStop = { reason: 'user', at: nowSeconds() };
        state.lastStopMessage = 'You turned the tunnel off.';
        setPhone('ready', 'The source device is ready.');
        state.checkedAt = nowSeconds();
        log('info', 'The simulated tunnel is off. No route or device changed.');
      }
    }

    if (state.pairing.state === 'connecting' && milliseconds >= state.pairing.confirmAt) {
      state.pairing.state = 'confirm';
      state.pairing.code = codeGenerator();
      state.pairing.completeAt = milliseconds + PAIR_CONFIRM_MS;
      log('info', 'The simulated pairing code is ready.');
    }
    if (state.pairing.state === 'confirm' && milliseconds >= state.pairing.completeAt) {
      state.pairing.state = 'paired';
      state.pairing.code = null;
      state.paired = true;
      state.trustedBySource = true;
      state.forget = { state: 'none', attempts: state.forget.attempts, endsAt: 0 };
      setPhone('ready', 'The source device is ready.');
      state.checkedAt = nowSeconds();
      state.counts.pairs += 1;
      log('info', 'The simulated pairing is complete. No source device was contacted.');
    }

    if (state.forget.state === 'pending' && milliseconds >= state.forget.endsAt) {
      state.forget.state = 'confirmed';
      state.forget.attempts += 1;
      state.paired = false;
      state.trustedBySource = null;
      state.connections = null;
      state.icmpEnabled = false;
      setPhone('unpaired', 'Pair with your source device to use it.');
      state.checkedAt = nowSeconds();
      state.pairing = { state: 'idle', code: null, error: null, confirmAt: 0, completeAt: 0 };
      state.counts.forgets += 1;
      log('info', 'The simulated pairing was forgotten. The demo source device keeps no trust.');
    }
  }

  function requireIdleAction() {
    if (state.operation) {
      throw new BackendError('busy', 'Wait for the current action to finish.', 409);
    }
  }

  function status() {
    advance();
    return {
      demo: true,
      running: state.running,
      mode: state.mode,
      paired: state.paired,
      icmp_enabled: state.running && state.mode === 'phone' && state.icmpEnabled,
      platform: {
        os: platform,
        arch: arch,
        admin: false,
        default_iface: null
      },
      phone: {
        state: state.phoneState,
        message: state.phoneMessage,
        checked_at: state.checkedAt,
        connections: state.running ? state.connections : null,
        trusted_by_source: state.trustedBySource,
        port_changed: state.portChanged
      },
      forget: {
        state: state.forget.state,
        attempts: state.forget.attempts
      },
      last_stop: {
        reason: state.lastStop.reason,
        at: state.lastStop.at
      },
      last_stop_message: state.lastStopMessage,
      engine: {
        version: appVersion,
        boundary: 'not_connected',
        tunnel: 'not_implemented'
      },
      uptime_s: Math.max(0, Math.round((nowMilliseconds() - state.startedAt) / 1000))
    };
  }

  function pairState() {
    advance();
    return {
      state: state.pairing.state,
      code: state.pairing.code,
      error: state.pairing.error
    };
  }

  function beginPairing() {
    advance();
    if (state.running) {
      throw new BackendError('tunnel_running', 'Turn off the tunnel first.', 409);
    }
    if (state.pairing.state === 'connecting' || state.pairing.state === 'confirm') {
      throw new BackendError('busy', 'Pairing is already running.', 409);
    }
    state.pairing = {
      state: 'connecting',
      code: null,
      error: null,
      confirmAt: nowMilliseconds() + PAIR_CONNECT_MS,
      completeAt: 0
    };
    log('info', 'The app started the simulated pairing. No network request was made.');
    return pairState();
  }

  function cancelPairing() {
    advance();
    const wasActive = state.pairing.state === 'connecting' || state.pairing.state === 'confirm';
    state.pairing = { state: 'idle', code: null, error: null, confirmAt: 0, completeAt: 0 };
    if (wasActive) log('info', 'The simulated pairing was cancelled.');
    return pairState();
  }

  function forget() {
    advance();
    if (state.running) {
      throw new BackendError('forget_blocked', 'Turn off the tunnel to forget this source device.', 409);
    }
    if (state.pairing.state === 'connecting' || state.pairing.state === 'confirm') {
      throw new BackendError('busy', 'Wait for the current action to finish.', 409);
    }
    state.forget = {
      state: 'pending',
      attempts: state.forget.attempts,
      endsAt: nowMilliseconds() + FORGET_DELAY_MS
    };
    log('info', 'The app sent the simulated Forget request. The record stays on this target device.');
    return {
      state: state.forget.state,
      attempts: state.forget.attempts
    };
  }

  function start(payload) {
    advance();
    const ping = payload && payload.ping === true;
    requireIdleAction();
    if (state.pairing.state === 'connecting' || state.pairing.state === 'confirm') {
      throw new BackendError('busy', 'Wait for the current action to finish.', 409);
    }
    if (state.running) {
      throw new BackendError('already_running', 'The tunnel is already on.', 409);
    }
    if (!state.paired || state.phoneState !== 'ready') {
      throw new BackendError('not_ready', 'The simulated source device is not ready. Pair first.', 409);
    }
    state.icmpEnabled = ping;
    state.operation = {
      kind: 'start',
      endsAt: nowMilliseconds() + START_DELAY_MS
    };
    state.counts.starts += 1;
    state.lastStopMessage = null;
    log('info', 'The app started the simulated tunnel. No route, TUN device, or outer socket is created.');
    return status();
  }

  function stop() {
    advance();
    requireIdleAction();
    if (!state.running) {
      return status();
    }
    state.operation = {
      kind: 'stop',
      endsAt: nowMilliseconds() + STOP_DELAY_MS
    };
    state.counts.stops += 1;
    log('info', 'The app is stopping the simulated tunnel.');
    return status();
  }

  function probe() {
    advance();
    const milliseconds = nowMilliseconds();
    if (state.probeLastAt && milliseconds - state.probeLastAt < PROBE_INTERVAL_MS) {
      throw new BackendError('rate_limited', 'Wait a moment and check again.', 429);
    }
    state.probeLastAt = milliseconds;
    state.counts.probes += 1;
    if (state.paired) {
      state.checkedAt = nowSeconds();
      state.trustedBySource = state.phoneState === 'not_trusted' ? false : true;
      if (state.phoneState === 'not_responding') {
        setPhone('ready', 'The source device answered the simulated check.');
        state.connections = state.running ? 3 : null;
        log('info', 'The simulated source device answered the check.');
      } else if (state.phoneState === 'not_trusted') {
        setPhone('not_trusted', 'The source device does not know this target device.');
        log('warn', 'The simulated source device does not trust this target device.');
      } else {
        setPhone(state.running ? 'ready' : state.phoneState, state.phoneMessage);
        log('info', 'The simulated source device answered the check.');
      }
    } else {
      state.checkedAt = nowSeconds();
      log('info', 'No source device is paired. The demo kept the unpaired state.');
    }
    return {
      phone: clone(status().phone)
    };
  }

  function activity(payload) {
    advance();
    const since = payload && Number.isInteger(payload.since) ? payload.since : 0;
    const entries = state.logs.filter(function (entry) { return entry.seq > since; }).slice(-200);
    const next = state.logs.length ? state.logs[state.logs.length - 1].seq : since;
    return { logs: clone(entries), next: next };
  }

  function failures() {
    advance();
    if (!state.failures) {
      return { since: null, total: 0, dropped: 0, demo: true, groups: [], recent: [] };
    }
    return clone(state.failures);
  }

  function diagnostics() {
    advance();
    const totalFailures = state.failures ? state.failures.total : 0;
    return {
      demo: true,
      running: state.running,
      engine: {
        version: appVersion,
        boundary: 'not_connected',
        tunnel: 'not_implemented',
        uptime_s: Math.max(0, Math.round((nowMilliseconds() - state.startedAt) / 1000)),
        workers: 1
      },
      setup: {
        connect_ms: { count: state.counts.starts, p50: 4, p95: 12, max: 38 },
        greeting_ms: { count: state.counts.starts, p50: 2, p95: 7, max: 21 },
        auth_ms: { count: state.counts.starts, p50: 2, p95: 6, max: 19 },
        request_ms: { count: state.counts.starts, p50: 5, p95: 14, max: 44 }
      },
      dns: {
        lookups: state.counts.starts * 4,
        ok: Math.max(0, state.counts.starts * 4 - totalFailures),
        failed: totalFailures,
        ms: { count: state.counts.starts * 4, p50: 3, p95: 9, max: 26 }
      },
      queues: {
        input: state.running ? [{ peak: 2, max_age_us: 900 }] : [],
        output: { peak: state.running ? 2 : 0, max_age_us: state.running ? 450 : 0 }
      },
      udp: {
        flows: state.counts.starts * 2,
        age_drops: 0
      },
      tcp: {
        flows_peak: state.running ? state.connections || 0 : 0,
        retransmits: 0,
        zero_window_ms: 0
      },
      failures: {
        total: totalFailures,
        dropped: state.failures ? state.failures.dropped : 0
      }
    };
  }

  function applyScenario(name) {
    advance();
    if (typeof name !== 'string' || SCENARIOS.indexOf(name) === -1) {
      throw new BackendError('invalid_scenario', 'The demo scenario is not known.');
    }
    if (name === 'reset') {
      reset();
      return status();
    }
    if (state.operation) {
      throw new BackendError('busy', 'Wait for the current action to finish.', 409);
    }
    if (name === 'ready') {
      state.paired = true;
      state.trustedBySource = true;
      state.running = false;
      state.mode = null;
      state.connections = null;
      state.icmpEnabled = false;
      state.operation = null;
      state.pairing = { state: 'paired', code: null, error: null, confirmAt: 0, completeAt: 0 };
      state.forget = { state: 'none', attempts: state.forget.attempts, endsAt: 0 };
      setPhone('ready', 'The source device is ready.');
      state.checkedAt = nowSeconds();
      log('info', 'Demo scenario: the simulated source device is ready.');
      return status();
    }
    if (name === 'source-stopped') {
      state.paired = true;
      state.trustedBySource = true;
      state.running = true;
      state.mode = 'phone';
      state.icmpEnabled = state.ping;
      state.connections = 0;
      state.operation = null;
      state.forget = { state: 'none', attempts: state.forget.attempts, endsAt: 0 };
      state.pairing = { state: 'paired', code: null, error: null, confirmAt: 0, completeAt: 0 };
      setPhone('not_responding', 'The source device stopped answering.');
      state.checkedAt = nowSeconds();
      seedFailures();
      log('warn', 'Demo scenario: the simulated source device stopped answering. The tunnel keeps the old state.');
      return status();
    }
    state.paired = true;
    state.trustedBySource = false;
    state.running = false;
    state.mode = null;
    state.connections = null;
    state.icmpEnabled = false;
    state.operation = null;
    state.forget = { state: 'none', attempts: state.forget.attempts, endsAt: 0 };
    state.pairing = { state: 'paired', code: null, error: null, confirmAt: 0, completeAt: 0 };
    setPhone('not_trusted', 'The source device does not know this target device.');
    state.checkedAt = nowSeconds();
    log('warn', 'Demo scenario: the simulated source device does not trust this target device.');
    return status();
  }

  return Object.freeze({
    mode: 'demo',
    status: status,
    pairState: pairState,
    beginPairing: beginPairing,
    cancelPairing: cancelPairing,
    forget: forget,
    start: start,
    stop: stop,
    probe: probe,
    activity: activity,
    failures: failures,
    diagnostics: diagnostics,
    applyScenario: applyScenario,
    reset: reset,
    dispose: function () {}
  });
}

module.exports = {
  BackendError: BackendError,
  SCENARIOS: SCENARIOS,
  createDemoBackend: createDemoBackend
};
