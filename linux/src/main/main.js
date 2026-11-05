'use strict';

/* HotspotShade for Linux.
 *
 * The app selects one backend at launch:
 *
 * - The in-memory demo backend is the default when no engine is configured.
 *   It is labeled as simulated in every view.
 * - The engine backend starts the HotspotShade binary named by an explicit
 *   `--engine` setting or by HOTSPOTSHADE_ENGINE. The main process passes a
 *   per-launch bearer secret on descriptor 3 and keeps the parent-liveness
 *   descriptor 4 open. The engine listens on 127.0.0.1 only.
 * - A packaged app uses the fixed pkexec helper. The app calls pkexec with the
 *   helper path and no other argument. The helper starts the packaged engine as
 *   root. The window, the renderer, and the engine client stay unprivileged.
 *
 * The renderer never receives the engine secret. It calls one fixed IPC
 * allowlist. The engine transport is in src/backend/engine-client.js.
 */

const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, Menu, Notification, Tray, clipboard, ipcMain, nativeImage, session } = require('electron');

const { createAutostart } = require('./autostart');
const { createDemoBackend } = require('../backend/demo-backend');
const { createEngineBoundary } = require('../backend/engine-boundary');
const { createEngineClient, resolveEngineConfig } = require('../backend/engine-client');
const { createEngineBackend, createUnavailableEngineBackend } = require('../backend/engine-backend');
const { createRouter, registerIpc } = require('./ipc');
const { wireLifecycle } = require('./lifecycle');
const { applySessionPolicy, hardenWebContents } = require('./security');
const { createMainWindow } = require('./window');
const { createSettingsWindow } = require('./settings-window');
const { buildApplicationMenu, sendMenuCommand } = require('./menu');
const { createElectronNotificationSink, createNotificationPolicy, sanitize } = require('./notifications');
const { createSettingsStore } = require('./settings');
const { createStatusMonitor } = require('./monitor');
const { createTray } = require('./tray');
const { ROOT_REFUSAL, shouldRefuse } = require('./root');

const APP_ROOT = path.join(__dirname, '..');
const RENDERER_ROOT = path.join(APP_ROOT, 'renderer');
const PRELOAD_PATH = path.join(__dirname, 'preload.js');
const ICON_PATH = path.join(APP_ROOT, '..', 'assets', 'icon.png');
const INDEX_URL = pathToFileURL(path.join(RENDERER_ROOT, 'index.html')).href;

const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;

app.enableSandbox();
app.setName('HotspotShade');

if (shouldRefuse(currentUid)) {
  console.error(ROOT_REFUSAL);
  app.exit(1);
} else {
  const hasSingleInstance = app.requestSingleInstanceLock();

  if (!hasSingleInstance) {
    app.quit();
  } else {
    let mainWindow = null;
    let settingsWindow = null;
    let backend = null;
    let boundary = null;
    let tray = null;
    let monitor = null;
    let notificationSink = null;
    let settingsStore = null;
    let unregisterIpc = null;
    let engineMode = false;
    let quitting = false;
    let trayBusy = false;

    function showMainWindow() {
      if (!mainWindow || mainWindow.isDestroyed()) return;
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }

    function notifyActionFailure(body) {
      if (!notificationSink || notificationSink.supported !== true || !settingsStore) return;
      if (settingsStore.snapshot().notifications !== true) return;
      notificationSink.post({
        kind: 'action',
        title: 'HotspotShade',
        body: sanitize(body, 200)
      });
    }

    function openSettingsWindow() {
      if (settingsWindow && !settingsWindow.isDestroyed()) {
        settingsWindow.show();
        settingsWindow.focus();
        return;
      }
      try {
        settingsWindow = createSettingsWindow({
          BrowserWindow: BrowserWindow,
          appRoot: RENDERER_ROOT,
          preloadPath: PRELOAD_PATH,
          iconPath: ICON_PATH,
          parent: mainWindow
        });
        hardenWebContents(settingsWindow.webContents, {
          indexUrl: INDEX_URL,
          onBlockedNavigation: function () {
            console.warn('Blocked a navigation request from the Settings page.');
          }
        });
        settingsWindow.on('closed', function () {
          settingsWindow = null;
        });
      } catch (error) {
        settingsWindow = null;
        console.error('The Settings window did not open.');
        showMainWindow();
        if (mainWindow && !mainWindow.isDestroyed()) {
          sendMenuCommand({ window: mainWindow, command: 'settings-inline' });
        }
      }
    }

    function runTrayAction(kind) {
      if (trayBusy || !backend) return;
      trayBusy = true;
      const action = kind === 'stop'
        ? backend.stop()
        : backend.start({ ping: settingsStore ? settingsStore.snapshot().ping : true });
      Promise.resolve(action).then(function () {
        if (monitor) return monitor.refreshNow();
        return undefined;
      }).catch(function (error) {
        console.error('The tray action did not finish: ' + (error && error.message ? error.message : 'unknown error'));
        notifyActionFailure(kind === 'stop'
          ? 'The tunnel did not stop. Open HotspotShade to read the status.'
          : 'The tunnel did not start. Open HotspotShade to read the status.');
      }).then(function () {
        trayBusy = false;
      }, function () {
        trayBusy = false;
      });
    }

    function createWindow() {
      mainWindow = createMainWindow({
        BrowserWindow: BrowserWindow,
        appRoot: RENDERER_ROOT,
        preloadPath: PRELOAD_PATH,
        iconPath: ICON_PATH
      });

      hardenWebContents(mainWindow.webContents, {
        indexUrl: INDEX_URL,
        onBlockedNavigation: function () {
          console.warn('Blocked a navigation request from the local page.');
        }
      });

      const menu = buildApplicationMenu({
        Menu: Menu,
        app: app,
        window: mainWindow,
        engineMode: engineMode,
        onSettings: openSettingsWindow,
        sendCommand: function (command) {
          sendMenuCommand({ window: mainWindow, command: command });
        },
        showAbout: function () {
          app.showAboutPanel();
        }
      });
      Menu.setApplicationMenu(menu);

      mainWindow.on('close', function (event) {
        if (quitting) return;
        if (tray && tray.available) {
          if (event && typeof event.preventDefault === 'function') event.preventDefault();
          mainWindow.hide();
        }
      });

      mainWindow.on('closed', function () {
        mainWindow = null;
      });
    }

    app.on('second-instance', function () {
      showMainWindow();
    });

    app.on('web-contents-created', function (_event, contents) {
      contents.setWindowOpenHandler(function () {
        return { action: 'deny' };
      });
      contents.on('will-attach-webview', function (event) {
        event.preventDefault();
      });
    });

    app.on('before-quit', function () {
      quitting = true;
    });

    app.on('will-quit', function () {
      if (monitor) monitor.stop();
      if (tray) {
        tray.destroy();
        tray = null;
      }
      if (settingsWindow && !settingsWindow.isDestroyed()) {
        settingsWindow.destroy();
        settingsWindow = null;
      }
    });

    app.whenReady().then(function () {
      const config = resolveEngineConfig({
        argv: process.argv.slice(1),
        env: process.env,
        isPackaged: app.isPackaged === true
      });

      let notificationsSupported = false;
      try {
        notificationsSupported = Notification.isSupported();
      } catch (error) {
        notificationsSupported = false;
      }

      const autostart = createAutostart({
        env: process.env,
        execPath: app.isPackaged === true
          ? (process.env.APPIMAGE || process.execPath)
          : ''
      });
      settingsStore = createSettingsStore({
        filePath: path.join(app.getPath('userData'), 'settings.json'),
        autostart: autostart,
        notificationsSupported: notificationsSupported
      });

      notificationSink = createElectronNotificationSink({
        Notification: Notification,
        iconPath: ICON_PATH,
        onClick: showMainWindow
      });

      if (config.mode === 'engine') {
        engineMode = true;
        const client = config.privileged
          ? createEngineClient({
            privileged: true,
            pkexecPath: config.pkexecPath,
            helperPath: config.helperPath,
            enginePath: config.enginePath
          })
          : createEngineClient({
            executable: config.executable,
            demo: config.demo === true
          });
        backend = createEngineBackend({ client: client });
        boundary = client;
        /* Start at once so the first status call does not wait for a cold
         * process. A startup failure is reported through the status route. */
        client.start().catch(function (error) {
          console.error('The engine did not start: ' + (error && error.message ? error.message : 'unknown error'));
        });
      } else if (config.mode === 'error') {
        engineMode = true;
        backend = createUnavailableEngineBackend(config.error);
        boundary = createEngineBoundary();
        console.error('The engine setting is not valid.');
      } else {
        backend = createDemoBackend({
          appVersion: app.getVersion(),
          platform: process.platform,
          arch: process.arch
        });
        boundary = createEngineBoundary();
      }

      const router = createRouter({
        backend: backend,
        boundary: boundary,
        clipboard: clipboard,
        settings: settingsStore,
        openSettings: openSettingsWindow,
        appInfo: {
          version: app.getVersion(),
          platform: process.platform,
          arch: process.arch
        },
        onInternalError: function () {
          console.error('The backend request failed.');
        }
      });

      applySessionPolicy(session.defaultSession, {
        rendererRoot: RENDERER_ROOT,
        onDeniedRequest: function () {
          console.warn('Blocked a non-local request from the local page.');
        },
        onInternalError: function () {
          console.error('The local session rejected an operation.');
        }
      });

      unregisterIpc = registerIpc({
        ipcMain: ipcMain,
        router: router,
        indexUrl: INDEX_URL,
        getWindows: function () {
          return [mainWindow, settingsWindow];
        }
      });

      buildTray();

      monitor = createStatusMonitor({
        backend: backend,
        sink: notificationSink,
        settingsStore: settingsStore,
        policy: createNotificationPolicy(),
        allowNotifications: engineMode && config.demo !== true,
        isFocused: function () {
          const focused = BrowserWindow.getFocusedWindow();
          return !!focused && !focused.isDestroyed();
        },
        onState: function (state) {
          if (tray) tray.update(state);
        },
        onError: function () {
          console.error('The status monitor did not finish one poll.');
        }
      });
      monitor.start();

      app.setAboutPanelOptions({
        applicationName: 'HotspotShade',
        applicationVersion: app.getVersion(),
        copyright: engineMode ? 'Linux engine service.' : 'Demo build. No tunnel.',
        credits: engineMode
          ? 'The app controls the local HotspotShade engine service. The engine listens on 127.0.0.1 only. The privileged helper starts the packaged engine with pkexec.'
          : 'A simulated Linux target app. This demo build starts no tunnel.',
        iconPath: ICON_PATH
      });

      createWindow();
    });

    function buildTray() {
      tray = createTray({
        Tray: Tray,
        Menu: Menu,
        nativeImage: nativeImage,
        iconPath: ICON_PATH,
        onStart: function () { runTrayAction('start'); },
        onStop: function () { runTrayAction('stop'); },
        onOpen: showMainWindow,
        onQuit: function () {
          quitting = true;
          app.quit();
        },
        onError: function () {
          console.warn('The tray item is not available on this desktop.');
        }
      });
      if (!tray.available) {
        console.warn('The desktop has no status notifier. The app runs without a tray item.');
      }
    }

    app.on('window-all-closed', function () {
      if (tray && tray.available && !quitting) return;
      app.quit();
    });

    /* Close the window and stop the engine in order. SIGTERM first, or the
     * helper request pipe for the privileged path. The app never restarts the
     * engine. */
    wireLifecycle({
      app: app,
      backend: {
        dispose: function () {
          if (monitor) monitor.stop();
          return backend ? backend.dispose() : undefined;
        }
      },
      engineMode: function () { return engineMode; },
      unregister: function () {
        if (unregisterIpc) unregisterIpc();
      },
      onError: function () {
        console.error('The engine did not stop in the expected time.');
      }
    });
  }
}
