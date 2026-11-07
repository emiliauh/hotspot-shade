import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  createTray,
  createTrayIcon,
  createTrayMenuTemplate,
  trayState
} = require('../src/main/tray.js');

test('the tray state follows the engine status', () => {
  assert.equal(trayState(null, null).label, 'Starting');
  const unavailable = trayState(null, null, true);
  assert.equal(unavailable.label, 'Not available');
  assert.equal(unavailable.startEnabled, false);
  assert.equal(unavailable.stopEnabled, false);
  const unknown = trayState({ running: true, paired: true, state: 'unknown' }, { state: 'idle' });
  assert.equal(unknown.label, 'Not available');
  assert.equal(unknown.startEnabled, false);
  assert.equal(unknown.stopEnabled, true);
  assert.equal(unknown.stopIsAttempt, true);
  const recoveryMenu = createTrayMenuTemplate({ status: { running: true, state: 'unknown' } });
  assert.equal(recoveryMenu[3].label, 'Try to turn off');
  assert.equal(recoveryMenu[3].enabled, true);
  let attempts = 0;
  const cleanupMenu = createTrayMenuTemplate({
    status: { running: true, cleanup_blocked: true },
    onStop() { attempts += 1; }
  });
  assert.equal(cleanupMenu[2].enabled, false);
  assert.equal(cleanupMenu[3].label, 'Try to turn off');
  assert.equal(cleanupMenu[3].enabled, true);
  cleanupMenu[3].click();
  assert.equal(attempts, 1);
  assert.equal(trayState({ running: true, state: 'unknown' }, null, true).stopEnabled, false);
  /* A pending cleanup mark is cleared only by a stop attempt, so the tray
   * offers it with a running false answer too. */
  const pending = trayState({ running: false, paired: true, cleanup_blocked: true, state: 'unknown' }, { state: 'idle' });
  assert.equal(pending.stopEnabled, true);
  assert.equal(pending.stopIsAttempt, true);
  assert.equal(pending.startEnabled, false);
  const pendingMenu = createTrayMenuTemplate({ status: { running: false, cleanup_blocked: true, state: 'unknown' } });
  assert.equal(pendingMenu[3].label, 'Try to turn off');
  assert.equal(pendingMenu[3].enabled, true);
  assert.equal(trayState({ running: false, paired: true, cleanup_blocked: true }, null, true).stopEnabled, false);
  assert.equal(trayState({ running: false, paired: false }, { state: 'idle' }).label, 'Not paired');
  assert.equal(trayState({ running: false, paired: true }, { state: 'idle' }).label, 'Ready');
  assert.equal(trayState({ running: false, paired: true, phone: { state: 'not_trusted' } }, { state: 'idle' }).label, 'Not trusted');
  const on = trayState({ running: true, paired: true }, { state: 'idle' });
  assert.equal(on.label, 'Tunnel on');
  assert.equal(on.startEnabled, false);
  assert.equal(on.stopEnabled, true);
  const demo = trayState({ demo: true, running: false, paired: false }, { state: 'idle' });
  assert.equal(demo.label, 'Not paired (demo)');
  assert.equal(demo.demo, true);
});

test('the tray requires an explicit running state before offering actions', () => {
  for (const running of [undefined, null, 'false']) {
    for (const mode of ['phone', 'direct']) {
      const view = trayState({ running, paired: true }, { state: 'idle' }, false, mode);
      assert.equal(view.label, 'Not available');
      assert.equal(view.startEnabled, false);
      assert.equal(view.stopEnabled, false);
    }
  }
  const unknownPairing = trayState({ running: false }, { state: 'idle' }, false, 'phone');
  assert.equal(unknownPairing.label, 'Not available');
  assert.equal(unknownPairing.startEnabled, false);
});

test('direct mode is ready without pairing, but unsafe status cannot start', () => {
  const status = { running: false, paired: false };
  const idle = { state: 'idle' };
  const direct = trayState(status, idle, false, 'direct');
  assert.equal(direct.label, 'Ready');
  assert.equal(direct.startEnabled, true);
  assert.equal(trayState(status, idle, false, 'phone').startEnabled, false);
  assert.equal(trayState(status, { state: 'confirm' }, false, 'direct').startEnabled, false);
  assert.equal(trayState(status, idle, true, 'direct').startEnabled, false);
  assert.equal(trayState({ ...status, cleanup_blocked: true }, idle, false, 'direct').startEnabled, false);
  assert.equal(trayState({ ...status, state: 'unknown' }, idle, false, 'direct').startEnabled, false);
});

test('Start, Stop, Open, and Quit are the only tray actions', () => {
  let started = 0;
  let stopped = 0;
  let opened = 0;
  let quit = 0;
  const template = createTrayMenuTemplate({
    status: { running: false, paired: true },
    pair: { state: 'idle' },
    onStart() { started += 1; },
    onStop() { stopped += 1; },
    onOpen() { opened += 1; },
    onQuit() { quit += 1; }
  });
  const labels = template.map((item) => item.label || item.type);
  assert.deepEqual(labels, [
    'HotspotShade. Ready',
    'separator',
    'Start tunnel',
    'Stop tunnel',
    'separator',
    'Open HotspotShade',
    'Quit HotspotShade'
  ]);
  template.find((item) => item.label === 'Start tunnel').click();
  template.find((item) => item.label === 'Start tunnel' && item.enabled === true).click();
  assert.equal(started, 2);
  assert.equal(template.find((item) => item.label === 'Stop tunnel').enabled, false);
  template.find((item) => item.label === 'Open HotspotShade').click();
  template.find((item) => item.label === 'Quit HotspotShade').click();
  assert.equal(opened, 1);
  assert.equal(quit, 1);
  assert.equal(stopped, 0);

  const demo = createTrayMenuTemplate({ status: { demo: true, running: false, paired: true }, pair: { state: 'idle' } });
  assert.ok(demo.some((item) => item.label === 'Start simulated tunnel'));
  assert.ok(demo.some((item) => item.label === 'Stop simulated tunnel'));

  const unavailable = createTrayMenuTemplate({ unavailable: true });
  assert.equal(unavailable[0].label, 'HotspotShade. Not available');
  assert.equal(unavailable.find((item) => item.label === 'Start tunnel').enabled, false);
  assert.equal(unavailable.find((item) => item.label === 'Stop tunnel').enabled, false);
});

test('the tray uses the local icon and updates the tooltip and menu', () => {
  const events = [];
  let trayInstance;
  class FakeTray {
    constructor(image) {
      trayInstance = this;
      this.image = image;
      this.tooltip = '';
      this.menu = null;
      this.handlers = {};
    }

    on(name, handler) {
      this.handlers[name] = handler;
    }

    setToolTip(value) {
      this.tooltip = value;
    }

    setContextMenu(menu) {
      this.menu = menu;
    }

    destroy() {
      events.push('destroy');
    }
  }
  const Menu = {
    buildFromTemplate(template) {
      return { template };
    }
  };
  const nativeImage = {
    createFromPath(file) {
      return {
        empty: false,
        isEmpty() { return false; },
        resize(size) { return { size, file }; }
      };
    }
  };
  let opened = 0;
  let started = 0;
  let tunnelMode = 'direct';
  const tray = createTray({
    Tray: FakeTray,
    Menu,
    nativeImage,
    iconPath: '/tmp/icon.png',
    onOpen() { opened += 1; },
    getTunnelMode() { return tunnelMode; },
    onStart() { started += 1; },
    onStop() {},
    onQuit() {}
  });
  assert.equal(tray.available, true);
  assert.equal(tray.state().label, 'Starting');
  tray.update({ status: { running: false, paired: false }, pair: { state: 'idle' } });
  assert.equal(tray.state().startEnabled, true);
  // A stale menu must not start phone mode after the setting changes.
  tunnelMode = 'phone';
  trayInstance.menu.template.find((item) => item.label === 'Start tunnel').click();
  assert.equal(started, 0);
  tray.update({ status: { running: true, paired: true }, pair: { state: 'idle' } });
  assert.equal(tray.state().label, 'Tunnel on');
  tray.update({ status: null, pair: null, unavailable: true });
  assert.equal(tray.state().label, 'Not available');
  tray.destroy();
  assert.deepEqual(events, ['destroy']);
  assert.equal(opened, 0);
});

test('a desktop without a status notifier gets the plain fallback', () => {
  class ThrowingTray {
    constructor() {
      throw new Error('no status notifier');
    }
  }
  let seen = null;
  const tray = createTray({
    Tray: ThrowingTray,
    Menu: { buildFromTemplate() { return {}; } },
    nativeImage: { createFromPath() { return { isEmpty() { return false; }, resize() { return {}; } }; } },
    iconPath: '/tmp/icon.png',
    onError(error) { seen = error; }
  });
  assert.equal(tray.available, false);
  assert.match(seen.message, /status notifier/);
  tray.update({ status: { running: true } });
  assert.equal(tray.state().label, 'Starting');
  tray.destroy();
});

test('a missing icon disables the tray item', () => {
  assert.equal(createTrayIcon({ createFromPath() { return { isEmpty() { return true; } }; } }, '/tmp/icon.png'), null);
  assert.equal(createTrayIcon(null, '/tmp/icon.png'), null);
  const tray = createTray({
    Tray: class {},
    Menu: { buildFromTemplate() { return {}; } },
    nativeImage: { createFromPath() { return { isEmpty() { return true; } }; } },
    iconPath: '/tmp/icon.png'
  });
  assert.equal(tray.available, false);
});
