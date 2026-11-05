'use strict';

/* Hermetic check for the separate Settings window.
 *
 * Run on Linux with a display:
 *   xvfb-run -a npm run test:settings-window
 *
 * The check loads the same renderer in a second BrowserWindow. It proves the
 * preload reports the settings window kind, the sidebar is hidden, the three
 * Settings sections are present, and the fixed IPC accepts the second window.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, clipboard, ipcMain, session } = require('electron');

const { createDemoBackend } = require('../src/backend/demo-backend');
const { createEngineBoundary } = require('../src/backend/engine-boundary');
const { createRouter, registerIpc } = require('../src/main/ipc');
const { applySessionPolicy, hardenWebContents } = require('../src/main/security');
const { createMainWindow } = require('../src/main/window');
const { createSettingsWindow } = require('../src/main/settings-window');
const { createTestSettingsStore } = require('./fixtures/test-settings');

const APP_ROOT = path.join(__dirname, '..');
const RENDERER_ROOT = path.join(APP_ROOT, 'src', 'renderer');
const PRELOAD_PATH = path.join(APP_ROOT, 'src', 'main', 'preload.js');
const ICON_PATH = path.join(APP_ROOT, 'assets', 'icon.png');
const INDEX_URL = pathToFileURL(path.join(RENDERER_ROOT, 'index.html')).href;
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-linux-settings-window-'));

const checks = [];
let mainWindow = null;
let settingsWindow = null;
let unregisterIpc = null;

function check(name, condition, detail) {
  checks.push({ name, ok: !!condition, detail: detail === undefined ? null : detail });
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function finish() {
  const ok = checks.every((item) => item.ok);
  console.log(JSON.stringify({ ok, checks }, null, 2));
  try {
    if (unregisterIpc) unregisterIpc();
  } catch (error) {
    /* Best effort. */
  }
  try {
    if (settingsWindow && !settingsWindow.isDestroyed()) settingsWindow.destroy();
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.destroy();
  } catch (error) {
    /* Best effort. */
  }
  try {
    fs.rmSync(USER_DATA, { recursive: true, force: true });
  } catch (error) {
    /* Best effort. */
  }
  app.exit(ok ? 0 : 1);
}

app.setPath('userData', USER_DATA);
app.enableSandbox();

app.whenReady().then(async () => {
  try {
    const backend = createDemoBackend({ appVersion: app.getVersion(), platform: process.platform, arch: process.arch });
    const boundary = createEngineBoundary();
    const router = createRouter({
      backend,
      boundary,
      clipboard,
      settings: createTestSettingsStore(USER_DATA),
      openSettings() {},
      appInfo: { version: app.getVersion(), platform: process.platform, arch: process.arch }
    });
    applySessionPolicy(session.defaultSession, { rendererRoot: RENDERER_ROOT });
    unregisterIpc = registerIpc({
      ipcMain,
      router,
      indexUrl: INDEX_URL,
      getWindows() { return [mainWindow, settingsWindow]; }
    });

    mainWindow = createMainWindow({
      BrowserWindow,
      appRoot: RENDERER_ROOT,
      preloadPath: PRELOAD_PATH,
      iconPath: ICON_PATH
    });
    hardenWebContents(mainWindow.webContents, { indexUrl: INDEX_URL });
    await new Promise((resolve) => mainWindow.webContents.once('did-finish-load', resolve));

    settingsWindow = createSettingsWindow({
      BrowserWindow,
      appRoot: RENDERER_ROOT,
      preloadPath: PRELOAD_PATH,
      iconPath: ICON_PATH,
      parent: mainWindow
    });
    hardenWebContents(settingsWindow.webContents, { indexUrl: INDEX_URL });
    await new Promise((resolve, reject) => {
      settingsWindow.webContents.once('did-finish-load', resolve);
      settingsWindow.webContents.once('did-fail-load', (_event, code, description) => {
        reject(new Error('The Settings page did not load: ' + description + ' (' + code + ')'));
      });
    });
    await wait(800);

    const view = await settingsWindow.webContents.executeJavaScript(`(() => ({
      windowKind: window.hotspotshade.windowKind,
      dataWindow: document.documentElement.getAttribute('data-window'),
      sidebar: getComputedStyle(document.querySelector('.sidebar')).display,
      title: document.title,
      settingsVisible: !document.getElementById('view-settings').hidden,
      dashboardVisible: !document.getElementById('view-dashboard').hidden,
      tabs: Array.from(document.querySelectorAll('[data-settings-tab]')).map((item) => item.textContent),
      generalVisible: !document.getElementById('settingsGeneralPanel').hidden,
      hasRequire: typeof require !== 'undefined',
      hasProcess: typeof process !== 'undefined',
      hasIpcRenderer: typeof window.ipcRenderer !== 'undefined'
    }))()`, true);

    check('the preload reports the settings window', view.windowKind === 'settings', view.windowKind);
    check('the page marks the settings window', view.dataWindow === 'settings', view.dataWindow);
    check('the sidebar is hidden', view.sidebar === 'none', view.sidebar);
    check('the window title names Settings', view.title.indexOf('HotspotShade Settings') === 0, view.title);
    check('the Settings view is visible', view.settingsVisible === true);
    check('the Dashboard view is hidden', view.dashboardVisible === false);
    check('the three Settings sections exist', view.tabs.join(',') === 'General,Pairing,Advanced', view.tabs);
    check('the General section is visible', view.generalVisible === true);
    check('the Settings page has no Node.js', view.hasRequire === false && view.hasProcess === false && view.hasIpcRenderer === false);

    const bootstrap = await settingsWindow.webContents.executeJavaScript('window.hotspotshade.bootstrap()', true);
    check('the fixed IPC accepts the Settings window', bootstrap && bootstrap.ok === true, bootstrap && bootstrap.error);
    check('the bootstrap answer has settings', !!(bootstrap && bootstrap.data && bootstrap.data.settings), bootstrap && bootstrap.data && bootstrap.data.settings);

    finish();
  } catch (error) {
    check('the Settings window check finished', false, error && error.message ? error.message : String(error));
    finish();
  }
});
