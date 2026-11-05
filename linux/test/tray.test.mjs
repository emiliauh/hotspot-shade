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
});

test('the tray uses the local icon and updates the tooltip and menu', () => {
  const events = [];
  class FakeTray {
    constructor(image) {
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
  const tray = createTray({
    Tray: FakeTray,
    Menu,
    nativeImage,
    iconPath: '/tmp/icon.png',
    onOpen() { opened += 1; },
    onStart() {},
    onStop() {},
    onQuit() {}
  });
  assert.equal(tray.available, true);
  assert.equal(tray.state().label, 'Starting');
  tray.update({ status: { running: true, paired: true }, pair: { state: 'idle' } });
  assert.equal(tray.state().label, 'Tunnel on');
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
