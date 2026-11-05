'use strict';

/* The narrow preload bridge.
 *
 * The page receives one frozen object with fixed methods. It cannot name an
 * IPC channel, load a module, read a file, open a socket, start a process, or
 * reach ipcRenderer. No secret or credential crosses this bridge.
 *
 * Each method returns the main-process envelope `{ok, data}` or
 * `{ok: false, error: {code, message}}`. The page unwraps the envelope. A
 * thrown Error would lose its custom `code` property across contextBridge.
 *
 * A sandboxed preload cannot load a local module, so the channel names and the
 * menu command names are repeated here. The asset test checks both lists.
 */

const { contextBridge, ipcRenderer } = require('electron');

const WINDOW_KIND_ARGUMENT = '--hs-window-kind=settings';
const windowKind = typeof process !== 'undefined'
  && Array.isArray(process.argv)
  && process.argv.includes(WINDOW_KIND_ARGUMENT)
  ? 'settings'
  : 'main';

const SETTING_NAMES = Object.freeze(['notifications', 'launchAtLogin', 'ping']);

const MENU_COMMANDS = Object.freeze([
  'dashboard',
  'activity',
  'settings',
  'settings-inline',
  'advanced',
  'refresh',
  'check-now',
  'theme',
  'demo-limitations',
  'demo-scenarios'
]);

function invoke(channel, payload) {
  return ipcRenderer.invoke(channel, payload);
}

contextBridge.exposeInMainWorld('hotspotshade', Object.freeze({
  windowKind: windowKind,
  bootstrap: function () {
    return invoke('hs:bootstrap');
  },
  status: function () {
    return invoke('hs:status');
  },
  pairState: function () {
    return invoke('hs:pair-state');
  },
  pair: function () {
    return invoke('hs:pair');
  },
  pairCancel: function () {
    return invoke('hs:pair-cancel');
  },
  forget: function () {
    return invoke('hs:forget');
  },
  start: function (options) {
    const ping = options && typeof options === 'object' && options.ping === true;
    return invoke('hs:start', { ping: ping });
  },
  stop: function () {
    return invoke('hs:stop');
  },
  probe: function () {
    return invoke('hs:probe');
  },
  activity: function (since) {
    return invoke('hs:activity', { since: Number.isInteger(since) ? since : -1 });
  },
  failures: function () {
    return invoke('hs:failures');
  },
  diagnostics: function () {
    return invoke('hs:diagnostics');
  },
  copyText: function (text) {
    return invoke('hs:copy-text', { text: typeof text === 'string' ? text : '' });
  },
  demoScenario: function (name) {
    return invoke('hs:demo-scenario', { name: typeof name === 'string' ? name : '' });
  },
  openSettings: function () {
    return invoke('hs:open-settings');
  },
  updateSetting: function (name, value) {
    if (!SETTING_NAMES.includes(name)) return Promise.resolve({ ok: false, error: { code: 'invalid_input', message: 'The request is not valid.' } });
    return invoke('hs:settings-update', { name: name, value: value === true });
  },
  onMenuCommand: function (handler) {
    if (typeof handler !== 'function') return function () {};
    const listener = function (_event, command) {
      if (MENU_COMMANDS.includes(command)) handler(command);
    };
    ipcRenderer.on('hs:menu-command', listener);
    return function () {
      ipcRenderer.removeListener('hs:menu-command', listener);
    };
  }
}));
