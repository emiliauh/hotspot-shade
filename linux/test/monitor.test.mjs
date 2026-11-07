import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createStatusMonitor, notificationsAllowedForConfig } = require('../src/main/monitor.js');
const { createNotificationPolicy } = require('../src/main/notifications.js');
const { trayState } = require('../src/main/tray.js');

function settings() {
  return {
    snapshot() {
      return {
        notifications: true,
        notificationsSupported: true,
        ping: true,
        launchAtLogin: false,
        launchAtLoginAvailable: true
      };
    }
  };
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

test('notifications are enabled only for a configured non-demo engine', () => {
  assert.equal(notificationsAllowedForConfig({ mode: 'engine' }), true);
  assert.equal(notificationsAllowedForConfig({ mode: 'engine', demo: true }), false);
  assert.equal(notificationsAllowedForConfig({ mode: 'error' }), false);
  assert.equal(notificationsAllowedForConfig({ mode: 'demo' }), false);
  assert.equal(notificationsAllowedForConfig(null), false);
});

test('an invalid engine configuration does not report an engine crash', async () => {
  const posts = [];
  const monitor = createStatusMonitor({
    backend: {
      status: async () => { throw new Error('invalid configuration'); },
      pairState: async () => ({})
    },
    settingsStore: settings(),
    sink: { supported: true, post(message) { posts.push(message); } },
    allowNotifications: notificationsAllowedForConfig({ mode: 'error' })
  });
  try {
    await monitor.refreshNow();
    await monitor.refreshNow();
    await monitor.refreshNow();
    assert.deepEqual(posts, []);
  } finally {
    monitor.stop();
  }
});

test('the monitor publishes status and sends one automatic stop message', async () => {
  const posts = [];
  const states = [];
  let running = true;
  const backend = {
    status() {
      return Promise.resolve({
        demo: false,
        running: running,
        paired: true,
        last_stop: running ? { reason: null, at: null } : { reason: 'hotspot_lost', at: 10 },
        last_stop_message: running ? null : 'The hotspot turned off, so HotspotShade turned the tunnel off.'
      });
    },
    pairState() {
      return Promise.resolve({ state: 'paired' });
    }
  };
  const monitor = createStatusMonitor({
    backend,
    settingsStore: settings(),
    policy: createNotificationPolicy({ now: () => 1000 }),
    sink: { supported: true, post(message) { posts.push(message); } },
    allowNotifications: true,
    intervalMs: 60000,
    onState(state) { states.push(state); }
  });
  monitor.start();
  await wait(30);
  assert.equal(states.length, 1);
  assert.equal(posts.length, 0);
  running = false;
  await monitor.refreshNow();
  assert.equal(posts.length, 1);
  assert.equal(posts[0].kind, 'auto-stop');
  await monitor.refreshNow();
  assert.equal(posts.length, 1);
  monitor.stop();
});

test('the monitor reports a gone engine once and keeps the page state empty', async () => {
  const posts = [];
  const states = [];
  const backend = {
    status() {
      return Promise.reject(new Error('The engine did not answer.'));
    },
    pairState() {
      return Promise.resolve({ state: 'idle' });
    }
  };
  const monitor = createStatusMonitor({
    backend,
    settingsStore: settings(),
    policy: createNotificationPolicy({ now: () => 1000 }),
    sink: { supported: true, post(message) { posts.push(message); } },
    allowNotifications: true,
    intervalMs: 60000,
    onState(state) { states.push(state); }
  });
  monitor.start();
  await wait(60);
  await monitor.refreshNow();
  await monitor.refreshNow();
  assert.equal(posts.length, 1);
  assert.equal(posts[0].kind, 'engine-gone');
  assert.equal(posts[0].body, 'The engine did not answer. Open HotspotShade to check its status.');
  assert.deepEqual(states[states.length - 1], { status: null, pair: null, unavailable: true });
  const last = states[states.length - 1];
  assert.equal(trayState(last.status, last.pair, last.unavailable).label, 'Not available');
  await monitor.refreshNow();
  assert.equal(posts.length, 1);
  monitor.stop();
});

test('engine-gone notifications are limited across separate failure episodes', async () => {
  const posts = [];
  let now = 1000;
  let broken = true;
  const monitor = createStatusMonitor({
    backend: {
      status: async () => { if (broken) throw new Error('offline'); return { running: false }; },
      pairState: async () => ({})
    },
    settingsStore: settings(),
    sink: { supported: true, post(message) { posts.push(message); } },
    allowNotifications: true,
    now: () => now
  });
  async function failEpisode() {
    broken = true;
    await monitor.refreshNow();
    await monitor.refreshNow();
    await monitor.refreshNow();
  }
  await failEpisode();
  broken = false;
  await monitor.refreshNow();
  now += 59999;
  await failEpisode();
  assert.equal(posts.filter((post) => post.kind === 'engine-gone').length, 1);
  broken = false;
  await monitor.refreshNow();
  now += 1;
  await failEpisode();
  assert.equal(posts.filter((post) => post.kind === 'engine-gone').length, 2);
  monitor.stop();
});

test('a throwing error reporter does not reject a monitor poll', async () => {
  let reports = 0;
  const monitor = createStatusMonitor({
    backend: { status: async () => ({}), pairState: async () => ({}) },
    settingsStore: settings(),
    onState() { throw new Error('state callback'); },
    onError() { reports += 1; throw new Error('error callback'); }
  });
  await assert.doesNotReject(monitor.refreshNow());
  assert.equal(reports, 1);
  monitor.stop();
});

test('a status success after stop does not publish', async () => {
  let complete;
  const states = [];
  const monitor = createStatusMonitor({
    backend: {
      status: () => new Promise((resolve) => { complete = resolve; }),
      pairState: async () => ({})
    },
    settingsStore: settings(),
    onState(state) { states.push(state); }
  });
  const pending = monitor.refreshNow();
  monitor.stop();
  complete({ running: true });
  await pending;
  assert.deepEqual(states, []);
});

test('refresh during a poll waits for a new status after that poll', async () => {
  let completeFirst;
  let calls = 0;
  const states = [];
  const monitor = createStatusMonitor({
    backend: {
      status() {
        calls += 1;
        if (calls === 1) return new Promise((resolve) => { completeFirst = resolve; });
        return Promise.resolve({ running: false });
      },
      pairState: async () => ({})
    },
    settingsStore: settings(),
    onState(state) { states.push(state.status.running); }
  });
  const first = monitor.refreshNow();
  const refresh = monitor.refreshNow();
  const sameRefresh = monitor.refreshNow();
  assert.equal(calls, 1);
  assert.equal(refresh, sameRefresh);
  completeFirst({ running: true });
  await Promise.all([first, refresh]);
  assert.equal(calls, 2);
  assert.deepEqual(states, [false]);
  assert.equal(monitor.getState().status.running, false);
  monitor.stop();
});

test('a refresh during the queued poll waits for another new poll', async () => {
  const pending = [];
  const states = [];
  const monitor = createStatusMonitor({
    backend: {
      status: () => new Promise((resolve) => { pending.push(resolve); }),
      pairState: async () => ({})
    },
    settingsStore: settings(),
    onState: (state) => states.push(state.status.running)
  });
  const first = monitor.refreshNow();
  const second = monitor.refreshNow();
  pending[0]({ running: true });
  await first;
  await wait(0);
  assert.equal(pending.length, 2);
  const third = monitor.refreshNow();
  pending[1]({ running: true });
  await second;
  await wait(0);
  assert.equal(pending.length, 3);
  assert.deepEqual(states, []);
  pending[2]({ running: false });
  await third;
  assert.deepEqual(states, [false]);
  monitor.stop();
});

test('an obsolete failed poll does not count toward engine-gone', async () => {
  let rejectFirst;
  let calls = 0;
  const states = [];
  const monitor = createStatusMonitor({
    backend: {
      status() {
        calls += 1;
        if (calls === 1) return new Promise((resolve, reject) => { rejectFirst = reject; });
        return Promise.reject(new Error('offline'));
      },
      pairState: async () => ({})
    },
    settingsStore: settings(),
    onState: (state) => states.push(state)
  });
  const first = monitor.refreshNow();
  const second = monitor.refreshNow();
  rejectFirst(new Error('old failure'));
  await Promise.all([first, second]);
  await monitor.refreshNow();
  assert.deepEqual(states, []);
  await monitor.refreshNow();
  assert.equal(states.length, 1);
  assert.equal(states[0].unavailable, true);
  monitor.stop();
});

test('a refresh suppresses a stale poll waiting for pairing state', async () => {
  let completePair;
  let pairCalls = 0;
  let statusCalls = 0;
  const states = [];
  const monitor = createStatusMonitor({
    backend: {
      status: async () => ({ running: ++statusCalls === 1 }),
      pairState() {
        pairCalls += 1;
        return pairCalls === 1
          ? new Promise((resolve) => { completePair = resolve; })
          : Promise.resolve({});
      }
    },
    settingsStore: settings(),
    onState: (state) => states.push(state.status.running)
  });
  const first = monitor.refreshNow();
  await wait(0);
  const refresh = monitor.refreshNow();
  completePair({ state: 'paired' });
  await Promise.all([first, refresh]);
  assert.deepEqual(states, [false]);
  monitor.stop();
});

test('stopping during a poll cancels a queued refresh', async () => {
  let completeFirst;
  let calls = 0;
  const monitor = createStatusMonitor({
    backend: {
      status() {
        calls += 1;
        return new Promise((resolve) => { completeFirst = resolve; });
      },
      pairState: async () => ({})
    },
    settingsStore: settings()
  });
  const first = monitor.refreshNow();
  const refresh = monitor.refreshNow();
  monitor.stop();
  completeFirst({ running: true });
  await Promise.all([first, refresh]);
  assert.equal(calls, 1);
});

test('a status rejection after stop neither publishes nor notifies', async () => {
  const posts = [];
  const states = [];
  let pendingReject = null;
  let deferred = false;
  const backend = {
    status() {
      if (!deferred) return Promise.reject(new Error('The engine did not answer.'));
      return new Promise((resolve, reject) => {
        pendingReject = reject;
      });
    },
    pairState() {
      return Promise.resolve({ state: 'idle' });
    }
  };
  const monitor = createStatusMonitor({
    backend,
    settingsStore: settings(),
    policy: createNotificationPolicy({ now: () => 1000 }),
    sink: { supported: true, post(message) { posts.push(message); } },
    allowNotifications: true,
    intervalMs: 60000,
    onState(state) { states.push(state); }
  });

  await monitor.refreshNow();
  await monitor.refreshNow();
  assert.deepEqual(posts, []);
  assert.deepEqual(states, []);

  deferred = true;
  const third = monitor.refreshNow();
  await wait(0);
  assert.equal(typeof pendingReject, 'function');
  monitor.stop();
  pendingReject(new Error('The engine stopped after the monitor stopped.'));
  await third;

  assert.deepEqual(states, []);
  assert.deepEqual(posts, []);
  assert.deepEqual(monitor.getState(), { status: null, pair: null });
});
