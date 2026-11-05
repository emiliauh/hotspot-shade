'use strict';

/* The fixed IPC router.
 *
 * The Electron wiring in this file is thin. The router is a pure object so the
 * Node tests can call every route with a fake backend, a fake boundary, and a
 * fake clipboard. No route accepts a channel name, path, URL, shell command,
 * host, token, or generic request body.
 */

const { IPC_CHANNELS } = require('./channels');
const { BackendError } = require('../backend/errors');
const { EngineUnavailableError } = require('../backend/engine-boundary');
const protocol = require('./protocol');

function failure(code, message) {
  return {
    ok: false,
    error: {
      code: code,
      message: message
    }
  };
}

function mapError(error, onInternalError) {
  if (error instanceof BackendError) {
    return failure(error.code, error.message);
  }
  if (error instanceof EngineUnavailableError) {
    return failure('engine_unavailable', error.message);
  }
  if (error instanceof protocol.ProtocolError) {
    return failure('invalid_input', 'The request is not valid.');
  }
  if (onInternalError) onInternalError(error);
  return failure('internal', 'The backend failed.');
}

function createRouter(dependencies) {
  const deps = dependencies && typeof dependencies === 'object' ? dependencies : {};
  const backend = deps.backend;
  const boundary = deps.boundary;
  const appInfo = deps.appInfo && typeof deps.appInfo === 'object' ? deps.appInfo : {};
  const clipboard = deps.clipboard;
  const settingsStore = deps.settings;
  const openSettings = typeof deps.openSettings === 'function' ? deps.openSettings : null;
  const onInternalError = typeof deps.onInternalError === 'function' ? deps.onInternalError : null;

  if (!backend || typeof backend.status !== 'function') {
    throw new TypeError('A backend is required.');
  }
  if (!boundary || typeof boundary.describe !== 'function') {
    throw new TypeError('An engine boundary is required.');
  }
  if (!settingsStore || typeof settingsStore.snapshot !== 'function') {
    throw new TypeError('A settings store is required.');
  }

  const routes = {
    bootstrap: {
      validate: protocol.noArgs,
      run: function () {
        const demo = backend.mode === 'demo';
        const engine = typeof backend.describeEngine === 'function'
          ? backend.describeEngine()
          : boundary.describe();
        return {
          app: {
            name: 'HotspotShade',
            version: typeof appInfo.version === 'string' ? appInfo.version : '0.1.0',
            platform: typeof appInfo.platform === 'string' ? appInfo.platform : 'linux',
            arch: typeof appInfo.arch === 'string' ? appInfo.arch : '',
            demo: demo
          },
          mode: backend.mode,
          demo: demo,
          engine: engine,
          settings: settingsStore.snapshot(),
          limits: {
            copyText: protocol.MAX_COPY_TEXT,
            activitySince: protocol.MAX_ACTIVITY_SINCE
          }
        };
      }
    },
    status: { validate: protocol.noArgs, run: function () { return backend.status(); } },
    pairState: { validate: protocol.noArgs, run: function () { return backend.pairState(); } },
    pair: { validate: protocol.noArgs, run: function () { return backend.beginPairing(); } },
    pairCancel: { validate: protocol.noArgs, run: function () { return backend.cancelPairing(); } },
    forget: { validate: protocol.noArgs, run: function () { return backend.forget(); } },
    start: { validate: protocol.startOptions, run: function (options) { return backend.start(options); } },
    stop: { validate: protocol.noArgs, run: function () { return backend.stop(); } },
    probe: { validate: protocol.noArgs, run: function () { return backend.probe(); } },
    activity: { validate: protocol.activityQuery, run: function (query) { return backend.activity(query); } },
    failures: { validate: protocol.noArgs, run: function () { return backend.failures(); } },
    diagnostics: { validate: protocol.noArgs, run: function () { return backend.diagnostics(); } },
    copyText: {
      validate: protocol.copyText,
      run: function (payload) {
        if (!clipboard || typeof clipboard.writeText !== 'function') {
          throw new BackendError('clipboard_unavailable', 'The clipboard is not available.');
        }
        clipboard.writeText(payload.text);
        return { copied: true };
      }
    },
    demoScenario: {
      validate: protocol.scenarioChoice,
      run: function (payload) {
        if (backend.mode !== 'demo' || typeof backend.applyScenario !== 'function') {
          throw new BackendError('demo_only', 'The demo scenario is not available.');
        }
        return backend.applyScenario(payload.name);
      }
    },
    openSettings: {
      validate: protocol.noArgs,
      run: function () {
        if (!openSettings) {
          throw new BackendError('unavailable', 'The Settings window is not available.');
        }
        openSettings();
        return { opened: true };
      }
    },
    settingsUpdate: {
      validate: protocol.settingUpdate,
      run: function (payload) {
        try {
          return settingsStore.update(payload.name, payload.value);
        } catch (error) {
          throw new BackendError('setting_failed', 'The setting could not be saved.');
        }
      }
    }
  };

  async function invoke(name, payload) {
    const route = Object.prototype.hasOwnProperty.call(routes, name) ? routes[name] : null;
    if (!route) return failure('invalid_request', 'The request is not available.');

    let value;
    try {
      value = route.validate(payload);
    } catch (error) {
      return failure('invalid_input', 'The request is not valid.');
    }

    try {
      const data = await route.run(value);
      return { ok: true, data: data };
    } catch (error) {
      return mapError(error, onInternalError);
    }
  }

  return Object.freeze({
    invoke: invoke,
    channelNames: Object.freeze(Object.keys(IPC_CHANNELS))
  });
}

function samePageUrl(candidate, expected) {
  try {
    const left = new URL(candidate);
    const right = new URL(expected);
    left.hash = '';
    right.hash = '';
    return left.href === right.href;
  } catch (error) {
    return false;
  }
}

function isTrustedSender(event, windowOrWindows, indexUrl) {
  const windows = Array.isArray(windowOrWindows) ? windowOrWindows : [windowOrWindows];
  try {
    if (!event || !event.sender) return false;
    const frame = event.senderFrame;
    if (!frame) return false;
    for (const window of windows) {
      if (!window || !window.webContents) continue;
      if (event.sender.id !== window.webContents.id) continue;
      if (frame !== window.webContents.mainFrame) continue;
      if (samePageUrl(frame.url, indexUrl)) return true;
    }
    return false;
  } catch (error) {
    return false;
  }
}

function registerIpc(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const ipcMain = settings.ipcMain;
  const router = settings.router;
  const indexUrl = settings.indexUrl;
  const getWindows = typeof settings.getWindows === 'function'
    ? settings.getWindows
    : function () { return [typeof settings.getWindow === 'function' ? settings.getWindow() : null]; };

  if (!ipcMain || typeof ipcMain.handle !== 'function') throw new TypeError('A fixed IPC main handle is required.');
  if (!router || typeof router.invoke !== 'function') throw new TypeError('A router is required.');
  if (typeof indexUrl !== 'string' || !indexUrl) throw new TypeError('The index URL is required.');

  const registered = [];

  Object.entries(IPC_CHANNELS).forEach(function (entry) {
    const name = entry[0];
    const channel = entry[1];
    ipcMain.handle(channel, function (event, payload) {
      const windows = getWindows();
      if (!isTrustedSender(event, Array.isArray(windows) ? windows : [windows], indexUrl)) {
        return failure('invalid_sender', 'The request was not accepted.');
      }
      return router.invoke(name, payload);
    });
    registered.push(channel);
  });

  return function unregister() {
    registered.forEach(function (channel) {
      if (typeof ipcMain.removeHandler === 'function') ipcMain.removeHandler(channel);
    });
  };
}

module.exports = {
  createRouter: createRouter,
  failure: failure,
  isTrustedSender: isTrustedSender,
  mapError: mapError,
  registerIpc: registerIpc,
  samePageUrl: samePageUrl
};
