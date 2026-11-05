'use strict';

/* Persisted desktop settings for the Linux target app.
 *
 * The main process owns the notification choice, the ping choice, and the
 * launch-at-login state. The page reads them from the bootstrap answer and
 * changes them through one bounded IPC route. The choices survive a restart.
 *
 * The launch-at-login state is the real XDG autostart file, not a copy. A
 * missing file reports off.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SETTING_NAMES = Object.freeze(['notifications', 'launchAtLogin', 'ping']);
const DEFAULTS = Object.freeze({
  notifications: true,
  ping: true
});

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function readBoolean(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

function atomicWriteJson(fileSystem, target, value) {
  const directory = path.dirname(target);
  fileSystem.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const suffix = crypto.randomBytes(6).toString('hex');
  const temporary = target + '.tmp-' + String(process.pid) + '-' + suffix;
  let descriptor = null;
  try {
    descriptor = fileSystem.openSync(temporary, 'wx', 0o600);
    fileSystem.writeFileSync(descriptor, JSON.stringify(value, null, 2) + '\n');
    try {
      fileSystem.fsyncSync(descriptor);
    } catch (error) {
      /* Some file systems cannot sync a file. The rename is still atomic. */
    }
    fileSystem.closeSync(descriptor);
    descriptor = null;
    fileSystem.renameSync(temporary, target);
  } catch (error) {
    if (descriptor !== null) {
      try {
        fileSystem.closeSync(descriptor);
      } catch (closeError) {
        /* Best effort. */
      }
    }
    try {
      fileSystem.unlinkSync(temporary);
    } catch (unlinkError) {
      /* Best effort. */
    }
    throw error;
  }
}

function createSettingsStore(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const fileSystem = settings.fs && typeof settings.fs === 'object' ? settings.fs : fs;
  const filePath = typeof settings.filePath === 'string' ? settings.filePath : '';
  const autostart = settings.autostart;
  const notificationsSupported = settings.notificationsSupported === true;

  if (!filePath || !path.isAbsolute(filePath)) {
    throw new TypeError('An absolute settings file path is required.');
  }
  if (!autostart || typeof autostart.status !== 'function') {
    throw new TypeError('An autostart record is required.');
  }

  let current = {
    notifications: DEFAULTS.notifications,
    ping: DEFAULTS.ping
  };

  function read() {
    let text = '';
    try {
      text = fileSystem.readFileSync(filePath, 'utf8');
    } catch (error) {
      if (error && error.code !== 'ENOENT') {
        /* A broken settings file falls back to the defaults. */
      }
      return;
    }
    let value = null;
    try {
      value = JSON.parse(text);
    } catch (error) {
      return;
    }
    if (!isPlainObject(value)) return;
    current = {
      notifications: readBoolean(value.notifications, DEFAULTS.notifications),
      ping: readBoolean(value.ping, DEFAULTS.ping)
    };
  }

  function write() {
    atomicWriteJson(fileSystem, filePath, current);
  }

  function snapshot() {
    const login = autostart.status();
    return {
      notifications: current.notifications,
      notificationsSupported: notificationsSupported,
      ping: current.ping,
      launchAtLogin: login.enabled === true,
      launchAtLoginAvailable: login.available === true
    };
  }

  function update(name, value) {
    if (!SETTING_NAMES.includes(name)) {
      throw new TypeError('The setting is not known.');
    }
    if (typeof value !== 'boolean') {
      throw new TypeError('The setting value must be true or false.');
    }
    if (name === 'launchAtLogin') {
      if (value) autostart.enable();
      else autostart.disable();
      return snapshot();
    }
    current = Object.assign({}, current, { [name]: value });
    write();
    return snapshot();
  }

  read();

  return Object.freeze({
    filePath: filePath,
    snapshot: snapshot,
    update: update
  });
}

module.exports = {
  DEFAULTS: DEFAULTS,
  SETTING_NAMES: SETTING_NAMES,
  createSettingsStore: createSettingsStore
};
