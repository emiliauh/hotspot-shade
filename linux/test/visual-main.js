'use strict';

/* Visual check helper for the Linux demo shell.
 *
 * This file is not part of the normal test run. It writes screenshots to
 * $HS_SHOT_DIR or /tmp/hotspotshade-linux-shots. It uses a temporary profile
 * and the normal sandbox. It creates no tunnel, route, device, or listener.
 *
 *   xvfb-run -a -s "-screen 0 1728x1200x24" \
 *     npx electron test/visual-main.js
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, Menu, clipboard, ipcMain, session } = require('electron');

const { createDemoBackend } = require('../src/backend/demo-backend');
const { createEngineBoundary } = require('../src/backend/engine-boundary');
const { createRouter, registerIpc } = require('../src/main/ipc');
const { applySessionPolicy, hardenWebContents } = require('../src/main/security');
const { createMainWindow } = require('../src/main/window');
const { buildApplicationMenu, sendMenuCommand } = require('../src/main/menu');
const { createTestSettingsStore } = require('./fixtures/test-settings');

const APP_ROOT = path.join(__dirname, '..');
const RENDERER_ROOT = path.join(APP_ROOT, 'src', 'renderer');
const PRELOAD_PATH = path.join(APP_ROOT, 'src', 'main', 'preload.js');
const ICON_PATH = path.join(APP_ROOT, 'assets', 'icon.png');
const INDEX_URL = pathToFileURL(path.join(RENDERER_ROOT, 'index.html')).href;
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-linux-visual-'));
const SHOT_DIR = process.env.HS_SHOT_DIR || path.join(os.tmpdir(), 'hotspotshade-linux-shots');

const shots = [];
let mainWindow = null;
let unregisterIpc = null;
let backend = null;
let boundary = null;

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function evaluate(source) {
  return mainWindow.webContents.executeJavaScript(source, true);
}

async function capture(name) {
  const image = await mainWindow.webContents.capturePage();
  const file = path.join(SHOT_DIR, name + '.png');
  fs.writeFileSync(file, image.toPNG());
  const size = image.getSize();
  shots.push({ name: name, file: file, width: size.width, height: size.height });
}

async function setSize(width, height) {
  mainWindow.setContentSize(width, height);
  await wait(300);
}

async function theme(value) {
  await evaluate("document.querySelector('[data-theme-pref=\"" + value + "\"]').click()");
  await wait(250);
}

async function scenario(name) {
  await evaluate("window.hotspotshade.demoScenario('" + name + "').then((result) => result.data)");
  await wait(1300);
}

async function view(name) {
  await evaluate("document.querySelector('.nav-item[data-view=\"" + name + "\"]').click()");
  await wait(250);
}

async function tab(name) {
  await evaluate("document.getElementById('settingsTab" + name + "').click()");
  await wait(600);
}

function cleanup() {
  try {
    if (unregisterIpc) unregisterIpc();
    if (backend) backend.dispose();
    if (boundary) boundary.dispose();
  } catch (error) {
    /* Best effort. */
  }
  try {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.destroy();
  } catch (error) {
    /* Best effort. */
  }
  try {
    fs.rmSync(USER_DATA, { recursive: true, force: true });
  } catch (error) {
    /* Best effort. */
  }
}

app.setPath('userData', USER_DATA);
app.enableSandbox();

app.whenReady().then(async () => {
  try {
    fs.mkdirSync(SHOT_DIR, { recursive: true });
    backend = createDemoBackend({
      appVersion: app.getVersion(),
      platform: process.platform,
      arch: process.arch
    });
    boundary = createEngineBoundary();
    const router = createRouter({
      backend: backend,
      boundary: boundary,
      clipboard: clipboard,
      settings: createTestSettingsStore(USER_DATA),
      openSettings: function () {
        sendMenuCommand({ window: mainWindow, command: 'settings-inline' });
      },
      appInfo: { version: app.getVersion(), platform: process.platform, arch: process.arch }
    });
    applySessionPolicy(session.defaultSession, { rendererRoot: RENDERER_ROOT });
    unregisterIpc = registerIpc({
      ipcMain: ipcMain,
      router: router,
      indexUrl: INDEX_URL,
      getWindow: function () {
        return mainWindow;
      }
    });

    mainWindow = createMainWindow({
      BrowserWindow: BrowserWindow,
      appRoot: RENDERER_ROOT,
      preloadPath: PRELOAD_PATH,
      iconPath: ICON_PATH
    });
    hardenWebContents(mainWindow.webContents, { indexUrl: INDEX_URL });
    const menu = buildApplicationMenu({
      Menu: Menu,
      app: app,
      window: mainWindow,
      sendCommand: function (command) {
        sendMenuCommand({ window: mainWindow, command: command });
      },
      showAbout: function () {}
    });
    Menu.setApplicationMenu(menu);

    await new Promise((resolve, reject) => {
      mainWindow.webContents.once('did-finish-load', resolve);
      mainWindow.webContents.once('did-fail-load', (_event, code, description) => {
        reject(new Error(description + ' (' + code + ')'));
      });
    });
    await wait(1400);
    await theme('light');
    await setSize(1440, 1000);

    await view('dashboard');
    await capture('01-dashboard-unpaired-1440-light');

    await evaluate("document.getElementById('primaryAction').click()");
    await wait(900);
    await capture('02-pairing-code-1440-light');
    await evaluate("document.getElementById('cancelPairing').click()");
    await wait(300);

    await scenario('ready');
    await capture('03-dashboard-ready-1440-light');

    await evaluate("document.getElementById('primaryAction').click()");
    await wait(1800);
    await capture('04-dashboard-on-1440-light');
    await evaluate("document.getElementById('primaryAction').click()");
    await wait(1100);
    await capture('05-dashboard-stopped-1440-light');

    await scenario('not-trusted');
    await capture('06-dashboard-not-trusted-1440-light');
    await scenario('ready');

    await view('activity');
    await capture('07-activity-1440-light');
    await evaluate("document.getElementById('activityDetailsToggle').click()");
    await wait(200);
    await capture('08-activity-details-1440-light');

    await view('settings');
    await tab('General');
    await capture('09-settings-general-1440-light');
    await tab('Pairing');
    await capture('10-settings-pairing-1440-light');
    await tab('Advanced');
    await evaluate("document.getElementById('failuresRefresh').click()");
    await wait(500);
    await capture('11-settings-advanced-1440-light');

    await theme('dark');
    await view('dashboard');
    await capture('12-dashboard-ready-1440-dark');
    await view('activity');
    await capture('13-activity-1440-dark');
    await view('settings');
    await tab('Advanced');
    await capture('14-settings-advanced-1440-dark');

    await theme('light');
    await setSize(1100, 900);
    await view('dashboard');
    await capture('15-dashboard-ready-1100-light');
    await view('activity');
    await capture('16-activity-1100-light');
    await view('settings');
    await tab('Advanced');
    await capture('17-settings-advanced-1100-light');

    await evaluate("document.getElementById('demoScenario').value = 'reset'; document.getElementById('applyScenario').click()");
    await wait(1400);
    await view('activity');
    await capture('18-activity-empty-1100-light');
    await view('settings');
    await tab('Advanced');
    await evaluate("document.getElementById('failuresRefresh').click()");
    await wait(500);
    await capture('19-failures-empty-1100-light');

    await theme('dark');
    await view('dashboard');
    await capture('20-dashboard-unpaired-1100-dark');

    console.log(JSON.stringify({ ok: true, shotDir: SHOT_DIR, shots: shots }, null, 2));
    cleanup();
    app.exit(0);
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    cleanup();
    app.exit(1);
  }
});
