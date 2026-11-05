import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ipc = require('../src/main/ipc.js');
const channels = require('../src/main/channels.js');
const protocol = require('../src/main/protocol.js');
const { BackendError } = require('../src/backend/demo-backend.js');
const { createEngineBoundary, createEngineBoundaryBackend } = require('../src/backend/engine-boundary.js');

function fakeBackend(overrides = {}) {
  const calls = [];
  const backend = {
    mode: 'demo',
    calls,
    status() { calls.push(['status']); return { demo: true, running: false, paired: false }; },
    pairState() { calls.push(['pairState']); return { state: 'idle' }; },
    beginPairing() { calls.push(['beginPairing']); return { state: 'connecting' }; },
    cancelPairing() { calls.push(['cancelPairing']); return { state: 'idle' }; },
    forget() { calls.push(['forget']); return { state: 'pending' }; },
    start(options) { calls.push(['start', options]); return { running: false }; },
    stop() { calls.push(['stop']); return { running: false }; },
    probe() { calls.push(['probe']); return { phone: { state: 'ready' } }; },
    activity(query) { calls.push(['activity', query]); return { logs: [], next: query.since }; },
    failures() { calls.push(['failures']); return { demo: true, groups: [] }; },
    diagnostics() { calls.push(['diagnostics']); return { demo: true }; },
    applyScenario(name) { calls.push(['applyScenario', name]); return { demo: true }; },
    dispose() {}
  };
  return Object.assign(backend, overrides);
}

function fakeSettings(overrides = {}) {
  const current = Object.assign({
    notifications: true,
    notificationsSupported: true,
    ping: true,
    launchAtLogin: false,
    launchAtLoginAvailable: true
  }, overrides);
  return {
    snapshot() { return Object.assign({}, current); },
    update(name, value) {
      if (name === 'launchAtLogin') current.launchAtLogin = value;
      else current[name] = value;
      return this.snapshot();
    }
  };
}

function routerFor(backend = fakeBackend(), clipboard = { writeText() {} }, settings = fakeSettings()) {
  return ipc.createRouter({
    backend,
    boundary: createEngineBoundary(),
    appInfo: { version: '0.1.0', platform: 'linux', arch: 'x64' },
    clipboard,
    settings,
    openSettings() {}
  });
}

test('bootstrap reports a fixed demo route and no secret', async () => {
  const router = routerFor();
  const result = await router.invoke('bootstrap', undefined);
  assert.equal(result.ok, true);
  assert.equal(result.data.demo, true);
  assert.equal(result.data.mode, 'demo');
  assert.equal(result.data.app.name, 'HotspotShade');
  assert.equal(result.data.engine.connected, false);
  assert.equal(result.data.engine.transport, 'not_connected');
  assert.equal(result.data.engine.tunnel, 'not_implemented');
  assert.equal(result.data.limits.copyText, protocol.MAX_COPY_TEXT);
  assert.equal(result.data.limits.activitySince, protocol.MAX_ACTIVITY_SINCE);
  assert.doesNotMatch(JSON.stringify(result.data), /token|secret|identity|key/i);
});

test('bootstrap reports the engine backend without a credential', async () => {
  const backend = fakeBackend({
    mode: 'engine',
    describeEngine() {
      return { connected: true, transport: 'loopback_http', tunnel: 'engine_service', operations: ['status'] };
    }
  });
  const router = routerFor(backend);
  const result = await router.invoke('bootstrap', undefined);
  assert.equal(result.ok, true);
  assert.equal(result.data.mode, 'engine');
  assert.equal(result.data.demo, false);
  assert.equal(result.data.app.demo, false);
  assert.equal(result.data.engine.connected, true);
  assert.equal(result.data.engine.transport, 'loopback_http');
  assert.doesNotMatch(JSON.stringify(result.data), /secret|token|identity|key/i);
});

test('bootstrap reports settings and the settings route is bounded', async () => {
  const settings = fakeSettings({ notifications: false, ping: false });
  const router = routerFor(fakeBackend(), { writeText() {} }, settings);
  const bootstrap = await router.invoke('bootstrap', undefined);
  assert.equal(bootstrap.ok, true);
  assert.equal(bootstrap.data.settings.notifications, false);
  assert.equal(bootstrap.data.settings.ping, false);
  assert.equal(bootstrap.data.settings.notificationsSupported, true);
  assert.equal(bootstrap.data.settings.launchAtLogin, false);

  const updated = await router.invoke('settingsUpdate', { name: 'notifications', value: true });
  assert.equal(updated.ok, true);
  assert.equal(updated.data.notifications, true);

  const login = await router.invoke('settingsUpdate', { name: 'launchAtLogin', value: true });
  assert.equal(login.ok, true);
  assert.equal(login.data.launchAtLogin, true);

  const badName = await router.invoke('settingsUpdate', { name: 'theme', value: true });
  assert.equal(badName.ok, false);
  assert.equal(badName.error.code, 'invalid_input');
  const badValue = await router.invoke('settingsUpdate', { name: 'ping', value: 'true' });
  assert.equal(badValue.ok, false);
  const extra = await router.invoke('settingsUpdate', { name: 'ping', value: true, path: '/tmp/x' });
  assert.equal(extra.ok, false);
});

test('the Settings route opens one fixed window callback', async () => {
  let opened = 0;
  const router = ipc.createRouter({
    backend: fakeBackend(),
    boundary: createEngineBoundary(),
    appInfo: {},
    clipboard: { writeText() {} },
    settings: fakeSettings(),
    openSettings() { opened += 1; }
  });
  const result = await router.invoke('openSettings', undefined);
  assert.equal(result.ok, true);
  assert.deepEqual(result.data, { opened: true });
  assert.equal(opened, 1);
});

test('every fixed route runs one backend method', async () => {
  const backend = fakeBackend();
  const router = routerFor(backend);
  const results = [];
  results.push(await router.invoke('status', undefined));
  results.push(await router.invoke('pairState', undefined));
  results.push(await router.invoke('pair', undefined));
  results.push(await router.invoke('pairCancel', undefined));
  results.push(await router.invoke('forget', undefined));
  results.push(await router.invoke('start', { ping: true }));
  results.push(await router.invoke('stop', undefined));
  results.push(await router.invoke('probe', undefined));
  results.push(await router.invoke('activity', { since: 4 }));
  results.push(await router.invoke('failures', undefined));
  results.push(await router.invoke('diagnostics', undefined));
  results.push(await router.invoke('demoScenario', { name: 'ready' }));
  results.forEach((result) => assert.equal(result.ok, true));

  assert.deepEqual(backend.calls, [
    ['status'],
    ['pairState'],
    ['beginPairing'],
    ['cancelPairing'],
    ['forget'],
    ['start', { ping: true }],
    ['stop'],
    ['probe'],
    ['activity', { since: 4 }],
    ['failures'],
    ['diagnostics'],
    ['applyScenario', 'ready']
  ]);
});

test('unknown routes and invalid payloads are refused', async () => {
  const router = routerFor();
  const unknown = await router.invoke('openUrl', { url: 'https://example.com' });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.error.code, 'invalid_request');

  const badStart = await router.invoke('start', { ping: true, iface: 'wlan0' });
  assert.equal(badStart.ok, false);
  assert.equal(badStart.error.code, 'invalid_input');

  const badSince = await router.invoke('activity', { since: -1 });
  assert.equal(badSince.ok, false);
  assert.equal(badSince.error.code, 'invalid_input');
});

test('copy text uses the provided clipboard only', async () => {
  let written = null;
  const router = routerFor(fakeBackend(), { writeText(value) { written = value; } });
  const result = await router.invoke('copyText', { text: 'A report.\nSecond line.' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.data, { copied: true });
  assert.equal(written, 'A report.\nSecond line.');

  const noClipboard = routerFor(fakeBackend(), null);
  const failed = await noClipboard.invoke('copyText', { text: 'A report.' });
  assert.equal(failed.ok, false);
  assert.equal(failed.error.code, 'clipboard_unavailable');
});

test('the demo scenario route refuses a non-demo backend', async () => {
  const backend = fakeBackend({ mode: 'engine' });
  const router = routerFor(backend);
  const result = await router.invoke('demoScenario', { name: 'ready' });
  assert.equal(result.ok, false);
  assert.equal(result.error.code, 'demo_only');
});

test('the protected engine route reports unavailable and starts nothing', async () => {
  const boundary = createEngineBoundary();
  const backend = createEngineBoundaryBackend(boundary);
  const router = ipc.createRouter({
    backend,
    boundary,
    appInfo: { version: '0.1.0', platform: 'linux', arch: 'x64' },
    clipboard: { writeText() {} },
    settings: fakeSettings()
  });
  const result = await router.invoke('status', undefined);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, 'engine_unavailable');
  assert.match(result.error.message, /not connected/);
  assert.equal(boundary.connected, false);
  const bootstrap = await router.invoke('bootstrap', undefined);
  assert.equal(bootstrap.ok, true);
  assert.equal(bootstrap.data.mode, 'engine');
  assert.equal(bootstrap.data.engine.connected, false);
});

test('a backend error keeps its plain code and message', async () => {
  const backend = fakeBackend({
    forget() { throw new BackendError('forget_blocked', 'Turn off the tunnel to forget this source device.', 409); }
  });
  const result = await routerFor(backend).invoke('forget', undefined);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, 'forget_blocked');
  assert.equal(result.error.message, 'Turn off the tunnel to forget this source device.');
});

test('an unexpected error becomes one fixed internal message', async () => {
  let seen = null;
  const backend = fakeBackend({ status() { throw new Error('raw detail that must not leak'); } });
  const router = ipc.createRouter({
    backend,
    boundary: createEngineBoundary(),
    appInfo: {},
    clipboard: { writeText() {} },
    settings: fakeSettings(),
    onInternalError(error) { seen = error; }
  });
  const result = await router.invoke('status', undefined);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, 'internal');
  assert.equal(result.error.message, 'The backend failed.');
  assert.equal(seen.message, 'raw detail that must not leak');
  assert.doesNotMatch(JSON.stringify(result), /raw detail/);
});

test('the fixed IPC wrapper checks the sender, the frame, and the page URL', async () => {
  const handlers = new Map();
  const ipcMain = {
    handle(channel, handler) { handlers.set(channel, handler); },
    removeHandler(channel) { handlers.delete(channel); }
  };
  const mainFrame = { url: 'file:///opt/hotspotshade/renderer/index.html' };
  const window = { webContents: { id: 7, mainFrame } };
  const router = routerFor();
  const unregister = ipc.registerIpc({
    ipcMain,
    router,
    indexUrl: 'file:///opt/hotspotshade/renderer/index.html',
    getWindow() { return window; }
  });

  assert.equal(handlers.size, Object.keys(channels.IPC_CHANNELS).length);
  const statusHandler = handlers.get(channels.IPC_CHANNELS.status);
  const good = await statusHandler({
    sender: window.webContents,
    senderFrame: mainFrame
  }, undefined);
  assert.equal(good.ok, true);

  const wrongSender = await statusHandler({
    sender: { id: 8 },
    senderFrame: mainFrame
  }, undefined);
  assert.equal(wrongSender.ok, false);
  assert.equal(wrongSender.error.code, 'invalid_sender');

  const wrongFrame = await statusHandler({
    sender: window.webContents,
    senderFrame: { url: mainFrame.url }
  }, undefined);
  assert.equal(wrongFrame.ok, false);
  assert.equal(wrongFrame.error.code, 'invalid_sender');

  const wrongUrl = await statusHandler({
    sender: window.webContents,
    senderFrame: mainFrame
  }, undefined);
  assert.equal(wrongUrl.ok, true);

  mainFrame.url = 'file:///opt/hotspotshade/renderer/index.html#activity';
  const hashUrl = await statusHandler({ sender: window.webContents, senderFrame: mainFrame }, undefined);
  assert.equal(hashUrl.ok, true);

  unregister();
  assert.equal(handlers.size, 0);
});

test('same-page URL checks strip only the hash', () => {
  const expected = 'file:///opt/hotspotshade/renderer/index.html';
  assert.equal(ipc.samePageUrl(expected, expected), true);
  assert.equal(ipc.samePageUrl(expected + '#settings', expected), true);
  assert.equal(ipc.samePageUrl(expected + '?x=1', expected), false);
  assert.equal(ipc.samePageUrl('https://example.com/', expected), false);
  assert.equal(ipc.samePageUrl('not a url', expected), false);
});
