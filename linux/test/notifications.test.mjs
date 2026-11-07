import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  ACTION_FAILURE,
  createActionFailureNotifier,
  createActionFailurePolicy,
  createElectronNotificationSink,
  createNotificationPolicy,
  sanitize
} = require('../src/main/notifications.js');
const { notificationsAllowedForConfig } = require('../src/main/monitor.js');

function status(overrides = {}) {
  return Object.assign({
    running: false,
    last_stop: { reason: null, at: null },
    last_stop_message: null
  }, overrides);
}

function evaluate(policy, overrides = {}) {
  return policy.evaluate(Object.assign({
    enabled: true,
    supported: true,
    isFocused: false,
    status: status(),
    pair: { state: 'idle' }
  }, overrides)).messages;
}

test('the first evaluation is not a new stop or pairing event', () => {
  const policy = createNotificationPolicy({ now: () => 1000 });
  assert.deepEqual(evaluate(policy, {
    status: status({ last_stop: { reason: 'hotspot_lost', at: 5 }, last_stop_message: 'The hotspot turned off.' }),
    pair: { state: 'paired' }
  }), []);
});

test('an automatic stop sends one message and a user stop sends none', () => {
  const policy = createNotificationPolicy({ now: () => 1000 });
  evaluate(policy);
  const hotspot = evaluate(policy, {
    status: status({ last_stop: { reason: 'hotspot_lost', at: 10 }, last_stop_message: 'The hotspot turned off, so HotspotShade turned the tunnel off.' })
  });
  assert.equal(hotspot.length, 1);
  assert.equal(hotspot[0].kind, 'auto-stop');
  assert.equal(hotspot[0].title, 'HotspotShade');
  assert.equal(hotspot[0].body, 'The hotspot turned off, so HotspotShade turned the tunnel off.');

  assert.deepEqual(evaluate(policy, {
    status: status({ last_stop: { reason: 'hotspot_lost', at: 10 }, last_stop_message: 'The hotspot turned off, so HotspotShade turned the tunnel off.' })
  }), []);

  const user = evaluate(policy, {
    status: status({ last_stop: { reason: 'user', at: 11 }, last_stop_message: 'You turned the tunnel off.' })
  });
  assert.deepEqual(user, []);
});

test('a source device stop uses the fixed text when the engine sends none', () => {
  const policy = createNotificationPolicy({ now: () => 1000 });
  evaluate(policy);
  const messages = evaluate(policy, {
    status: status({ last_stop: { reason: 'source_device_gone', at: 20 } })
  });
  assert.equal(messages.length, 1);
  assert.match(messages[0].body, /source device stopped answering/);
});

test('an error stop is quiet while the app is focused', () => {
  const policy = createNotificationPolicy({ now: () => 1000 });
  evaluate(policy);
  assert.deepEqual(evaluate(policy, {
    isFocused: true,
    status: status({ last_stop: { reason: 'error', at: 1 }, last_stop_message: 'The engine stopped.' })
  }), []);
  const messages = evaluate(policy, {
    isFocused: false,
    status: status({ last_stop: { reason: 'error', at: 2 }, last_stop_message: 'The engine stopped.' })
  });
  assert.equal(messages.length, 1);
  assert.equal(messages[0].kind, 'tunnel-error');
});

test('a pairing result sends one message after an active pairing', () => {
  const policy = createNotificationPolicy({ now: () => 1000 });
  evaluate(policy, { pair: { state: 'idle' } });
  evaluate(policy, { pair: { state: 'connecting' } });
  const paired = evaluate(policy, { pair: { state: 'paired' } });
  assert.equal(paired.length, 1);
  assert.equal(paired[0].kind, 'pairing');
  assert.equal(paired[0].body, 'Paired with your source device.');

  const failedPolicy = createNotificationPolicy({ now: () => 1000 });
  evaluate(failedPolicy, { pair: { state: 'idle' } });
  evaluate(failedPolicy, { pair: { state: 'confirm', code: '123456' } });
  const failed = evaluate(failedPolicy, { pair: { state: 'failed', error: 'The code did not match.' } });
  assert.equal(failed.length, 1);
  assert.equal(failed[0].body, 'The code did not match.');
});

test('the setting and desktop support gate every message', () => {
  const disabled = createNotificationPolicy({ now: () => 1000 });
  evaluate(disabled, { enabled: false });
  assert.deepEqual(evaluate(disabled, {
    enabled: false,
    status: status({ last_stop: { reason: 'hotspot_lost', at: 1 } })
  }), []);

  const unsupported = createNotificationPolicy({ now: () => 1000 });
  evaluate(unsupported, { supported: false });
  assert.deepEqual(evaluate(unsupported, {
    supported: false,
    status: status({ last_stop: { reason: 'hotspot_lost', at: 1 } })
  }), []);
});

test('each kind is limited to one message in the debounce window', () => {
  let clock = 1000;
  const policy = createNotificationPolicy({ now: () => clock });
  evaluate(policy);
  const first = evaluate(policy, {
    status: status({ last_stop: { reason: 'hotspot_lost', at: 1 } })
  });
  assert.equal(first.length, 1);
  clock += 1000;
  const second = evaluate(policy, {
    status: status({ last_stop: { reason: 'source_device_gone', at: 2 } })
  });
  assert.deepEqual(second, []);
  clock += 60000;
  const third = evaluate(policy, {
    status: status({ last_stop: { reason: 'hotspot_lost', at: 3 } })
  });
  assert.equal(third.length, 1);
});

function actionNotifier(options = {}) {
  let clock = 1000;
  const posts = [];
  const sink = Object.prototype.hasOwnProperty.call(options, 'sink')
    ? options.sink
    : { supported: true, post(message) { posts.push(message); return true; } };
  const settingsStore = Object.prototype.hasOwnProperty.call(options, 'settingsStore')
    ? options.settingsStore
    : { snapshot() { return { notifications: options.notifications !== false }; } };
  const notifier = createActionFailureNotifier({
    sink,
    settingsStore,
    allowNotifications: options.allow !== false,
    policy: createActionFailurePolicy({ now: () => clock })
  });
  return {
    notifier,
    posts,
    advance(milliseconds) {
      clock += milliseconds;
    }
  };
}

test('a tray action failure uses fixed text and a separate limit for each action', () => {
  const { notifier, posts, advance } = actionNotifier();

  assert.equal(notifier.notify('start'), true);
  assert.equal(posts.length, 1);
  assert.equal(posts[0].kind, 'action-start');
  assert.equal(posts[0].title, 'HotspotShade');
  assert.equal(posts[0].body, ACTION_FAILURE.start);
  assert.equal(posts[0].body, 'The tunnel did not start. Open HotspotShade to read the status.');

  assert.equal(notifier.notify('start'), false);
  assert.equal(posts.length, 1);

  assert.equal(notifier.notify('stop'), true);
  assert.equal(posts.length, 2);
  assert.equal(posts[1].kind, 'action-stop');
  assert.equal(posts[1].body, ACTION_FAILURE.stop);
  assert.equal(posts[1].body, 'The tunnel did not stop. Open HotspotShade to read the status.');

  advance(59999);
  assert.equal(notifier.notify('start'), false);
  advance(1);
  assert.equal(notifier.notify('start'), true);
  assert.equal(posts.length, 3);
});

test('demo and invalid-engine configurations stay silent for tray action failures', () => {
  for (const config of [
    { mode: 'demo' },
    { mode: 'error' },
    { mode: 'engine', demo: true }
  ]) {
    const { notifier, posts } = actionNotifier({
      allow: notificationsAllowedForConfig(config)
    });
    assert.equal(notifier.notify('start'), false);
    assert.deepEqual(posts, []);
  }
});

test('the notification setting, desktop support, and a failing store gate action failures', () => {
  const disabled = actionNotifier({ notifications: false });
  assert.equal(disabled.notifier.notify('stop'), false);
  assert.deepEqual(disabled.posts, []);

  const unsupported = actionNotifier({ sink: { supported: false, post() { throw new Error('must not post'); } } });
  assert.equal(unsupported.notifier.notify('stop'), false);
  assert.deepEqual(unsupported.posts, []);

  const unreadable = actionNotifier({
    settingsStore: { snapshot() { throw new Error('The settings file is unreadable.'); } }
  });
  assert.equal(unreadable.notifier.notify('start'), false);
  assert.deepEqual(unreadable.posts, []);

  const failingSink = actionNotifier({
    sink: { supported: true, post() { throw new Error('The desktop rejected the message.'); } }
  });
  assert.equal(failingSink.notifier.notify('start'), false);
  assert.deepEqual(failingSink.posts, []);
});

test('message text is one bounded line and holds no control character', () => {
  assert.equal(sanitize('a\n b\tc'), 'a b c');
  assert.equal(sanitize('\u0000secret'), 'secret');
  assert.equal(sanitize('x'.repeat(400)).length, 240);
  assert.equal(sanitize(42), '');
});

test('the system sink keeps one message per kind and closes it', () => {
  const posts = [];
  const closed = [];
  class FakeNotification {
    static isSupported() {
      return true;
    }

    constructor(options) {
      this.options = options;
      this.handlers = {};
    }

    on(name, handler) {
      this.handlers[name] = handler;
    }

    show() {
      posts.push(this);
    }

    close() {
      closed.push(this);
    }
  }
  let clicked = 0;
  const sink = createElectronNotificationSink({
    Notification: FakeNotification,
    iconPath: '/tmp/icon.png',
    onClick() { clicked += 1; }
  });
  assert.equal(sink.supported, true);
  assert.equal(sink.post({ kind: 'auto-stop', title: 'HotspotShade', body: 'one' }), true);
  assert.equal(sink.post({ kind: 'auto-stop', title: 'HotspotShade', body: 'two' }), true);
  assert.equal(posts.length, 2);
  assert.equal(closed.length, 1);
  assert.equal(posts[1].options.body, 'two');
  posts[1].handlers.click();
  assert.equal(clicked, 1);
  sink.clearDelivered();
  assert.equal(closed.length, 2);
  assert.doesNotMatch(JSON.stringify(posts.map((item) => item.options)), /token|secret/i);
});
