import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createStatusMonitor } = require('../src/main/monitor.js');
const { createNotificationPolicy } = require('../src/main/notifications.js');

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
  assert.deepEqual(states[states.length - 1], { status: null, pair: null });
  await monitor.refreshNow();
  assert.equal(posts.length, 1);
  monitor.stop();
});
