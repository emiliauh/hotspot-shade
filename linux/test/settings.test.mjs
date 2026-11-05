import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  createAutostart,
  desktopEntryText,
  desktopQuote,
  resolveAutostartDirectory
} = require('../src/main/autostart.js');
const { createSettingsStore } = require('../src/main/settings.js');
const root = require('../src/main/root.js');

function temporaryDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-settings-'));
}

function fakeAutostart(initial = false) {
  let enabled = initial;
  return {
    status() {
      return { available: true, enabled };
    },
    enable() {
      enabled = true;
    },
    disable() {
      enabled = false;
    }
  };
}

test('the autostart directory follows XDG, HOME, and the test override', () => {
  assert.equal(resolveAutostartDirectory({ HS_AUTOSTART_DIR: '/tmp/hs-auto' }), '/tmp/hs-auto');
  assert.equal(resolveAutostartDirectory({ HS_AUTOSTART_DIR: 'relative' }), '');
  assert.equal(resolveAutostartDirectory({ XDG_CONFIG_HOME: '/home/user/.config' }), '/home/user/.config/autostart');
  assert.equal(resolveAutostartDirectory({ HOME: '/home/user' }), '/home/user/.config/autostart');
  assert.equal(resolveAutostartDirectory({}), '');
  assert.equal(resolveAutostartDirectory({ XDG_CONFIG_HOME: 'relative', HOME: '/home/user' }), '/home/user/.config/autostart');
});

test('the desktop entry quotes the program path and names no secret', () => {
  assert.equal(desktopQuote('/opt/HotspotShade'), '"/opt/HotspotShade"');
  assert.equal(desktopQuote('/opt/a b/$x`y"z\\'), '"/opt/a b/\\$x\\`y\\"z\\\\"');
  assert.equal(desktopQuote('/opt/100%/app'), '"/opt/100%%/app"');
  const entry = desktopEntryText('/opt/hotspotshade/HotspotShade');
  assert.match(entry, /^\[Desktop Entry\]/);
  assert.match(entry, /^Name=HotspotShade$/m);
  assert.match(entry, /^Exec="\/opt\/hotspotshade\/HotspotShade"$/m);
  assert.match(entry, /^X-GNOME-Autostart-enabled=true$/m);
  assert.doesNotMatch(entry, /token|secret|password/i);
});

test('the autostart file is written atomically and removed idempotently', () => {
  const directory = temporaryDirectory();
  try {
    const autostart = createAutostart({
      env: { HS_AUTOSTART_DIR: directory },
      execPath: '/opt/hotspotshade/HotspotShade'
    });
    assert.equal(autostart.available(), true);
    assert.equal(autostart.enabled(), false);
    autostart.enable();
    assert.equal(autostart.enabled(), true);
    const target = autostart.filePath();
    assert.equal(path.dirname(target), directory);
    assert.equal(fs.readFileSync(target, 'utf8'), autostart.text());
    assert.equal(fs.statSync(target).mode & 0o777, 0o644);
    const leftovers = fs.readdirSync(directory).filter((name) => name.includes('.tmp-'));
    assert.deepEqual(leftovers, []);
    autostart.disable();
    autostart.disable();
    assert.equal(autostart.enabled(), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('a failed rename removes the temporary file', () => {
  const directory = temporaryDirectory();
  try {
    const broken = Object.create(fs);
    broken.renameSync = function () {
      throw new Error('rename failed');
    };
    const autostart = createAutostart({
      fs: broken,
      env: { HS_AUTOSTART_DIR: directory },
      execPath: '/opt/hotspotshade/HotspotShade'
    });
    assert.throws(() => autostart.enable(), /rename failed/);
    assert.equal(autostart.enabled(), false);
    const leftovers = fs.readdirSync(directory).filter((name) => name.includes('.tmp-'));
    assert.deepEqual(leftovers, []);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('settings default, persist, and reload', () => {
  const directory = temporaryDirectory();
  try {
    const filePath = path.join(directory, 'settings.json');
    const autostart = fakeAutostart(false);
    const store = createSettingsStore({ filePath, autostart, notificationsSupported: true });
    assert.deepEqual(store.snapshot(), {
      notifications: true,
      notificationsSupported: true,
      ping: true,
      launchAtLogin: false,
      launchAtLoginAvailable: true
    });
    store.update('notifications', false);
    store.update('ping', false);
    store.update('launchAtLogin', true);
    assert.equal(autostart.status().enabled, true);

    const reloaded = createSettingsStore({ filePath, autostart, notificationsSupported: true });
    const value = reloaded.snapshot();
    assert.equal(value.notifications, false);
    assert.equal(value.ping, false);
    assert.equal(value.launchAtLogin, true);
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
    assert.doesNotMatch(fs.readFileSync(filePath, 'utf8'), /secret|token/i);

    reloaded.update('launchAtLogin', false);
    assert.equal(autostart.status().enabled, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('a broken settings file falls back to the defaults', () => {
  const directory = temporaryDirectory();
  try {
    const filePath = path.join(directory, 'settings.json');
    fs.writeFileSync(filePath, '{not json');
    const store = createSettingsStore({
      filePath,
      autostart: fakeAutostart(false),
      notificationsSupported: false
    });
    const value = store.snapshot();
    assert.equal(value.notifications, true);
    assert.equal(value.ping, true);
    assert.equal(value.notificationsSupported, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('the root guard refuses uid zero only', () => {
  assert.equal(root.isRootUid(0), true);
  assert.equal(root.isRootUid(1000), false);
  assert.equal(root.isRootUid(null), false);
  assert.equal(root.isRootUid('0'), false);
  assert.equal(root.shouldRefuse(0), true);
  assert.match(root.ROOT_REFUSAL, /must not run as root/);
});
