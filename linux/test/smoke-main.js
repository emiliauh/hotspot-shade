'use strict';

/* Hermetic Electron smoke test for the Linux demo shell.
 *
 * Run on Linux with a display, for example:
 *   xvfb-run -a npx electron test/smoke-main.js
 *
 * The test uses a temporary user-data directory. It creates no tunnel, route,
 * TUN device, listener, or external request. It runs with the normal sandbox.
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
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-linux-smoke-'));

const results = [];
const pageErrors = [];
const deniedRequests = [];
const createdWindows = [];
let mainWindow = null;
let unregisterIpc = null;
let backend = null;
let boundary = null;

function check(name, condition, detail) {
  results.push({ name: name, ok: !!condition, detail: detail === undefined ? null : detail });
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function evaluate(source) {
  return mainWindow.webContents.executeJavaScript(source, true);
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

function finish(ok) {
  const report = {
    ok: ok,
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
    checks: results,
    deniedRequests: deniedRequests.length,
    pageErrors: pageErrors
  };
  console.log(JSON.stringify(report, null, 2));
  cleanup();
  app.exit(ok ? 0 : 1);
}

app.setPath('userData', USER_DATA);
app.enableSandbox();

app.on('browser-window-created', (_event, window) => {
  createdWindows.push(window);
});

app.whenReady().then(async () => {
  try {
    backend = createDemoBackend({
      appVersion: app.getVersion(),
      platform: process.platform,
      arch: process.arch
    });
    boundary = createEngineBoundary();
    const settingsStore = createTestSettingsStore(USER_DATA);

    const router = createRouter({
      backend: backend,
      boundary: boundary,
      clipboard: clipboard,
      settings: settingsStore,
      openSettings: function () {
        sendMenuCommand({ window: mainWindow, command: 'settings-inline' });
      },
      appInfo: { version: app.getVersion(), platform: process.platform, arch: process.arch },
      onInternalError: function () {
        pageErrors.push('The demo backend request failed.');
      }
    });

    applySessionPolicy(session.defaultSession, {
      rendererRoot: RENDERER_ROOT,
      onDeniedRequest: function (url) {
        deniedRequests.push(url);
      }
    });

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

    mainWindow.webContents.on('console-message', (...args) => {
      let message = '';
      let level = 0;
      const details = args.find((value) => value && typeof value === 'object' && typeof value.message === 'string');
      if (details) {
        message = details.message;
        level = Number(details.level);
      } else {
        message = typeof args[2] === 'string' ? args[2] : '';
        level = Number(args[1]) || 0;
      }
      if (message && level >= 2) pageErrors.push(message);
    });

    mainWindow.webContents.on('render-process-gone', (_event, details) => {
      pageErrors.push('The renderer stopped: ' + details.reason);
    });

    await new Promise((resolve, reject) => {
      mainWindow.webContents.once('did-finish-load', resolve);
      mainWindow.webContents.once('did-fail-load', (_event, code, description) => {
        reject(new Error('The page did not load: ' + description + ' (' + code + ')'));
      });
    });

    await wait(1400);

    const initial = await evaluate(`(() => ({
      title: document.title,
      heading: document.getElementById('dashboardTitle').textContent,
      hasBridge: typeof window.hotspotshade === 'object',
      hasRequire: typeof require !== 'undefined',
      hasProcess: typeof process !== 'undefined',
      hasIpcRenderer: typeof window.ipcRenderer !== 'undefined',
      bridgeFrozen: Object.isFrozen(window.hotspotshade),
      demoText: document.body.textContent.includes('Demo mode. Data is simulated.'),
      bannerVisible: !document.getElementById('demoBanner').hidden,
      pillVisible: !document.getElementById('demoPill').hidden,
      demoLineVisible: !document.getElementById('demoLine').hidden,
      csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]').content,
      theme: document.documentElement.getAttribute('data-theme'),
      shellDisplay: getComputedStyle(document.querySelector('.app-shell')).display,
      brandWidth: getComputedStyle(document.querySelector('.brand-mark svg')).width,
      sourceTop: document.getElementById('sourceCardTitle').closest('.card').getBoundingClientRect().top,
      connectionTop: document.getElementById('connectionCardTitle').closest('.card').getBoundingClientRect().top,
      resources: performance.getEntriesByType('resource').map((entry) => entry.name),
      platform: document.getElementById('platformText').textContent,
      menuBarVisible: true
    }))()`);

    check('the page loaded', initial.title.indexOf('HotspotShade (Demo)') === 0, initial.title);
    check('the application stylesheet is applied', initial.shellDisplay === 'grid' && initial.brandWidth === '20px', initial.shellDisplay + ', ' + initial.brandWidth);
    check('dashboard cards align', Math.abs(initial.sourceTop - initial.connectionTop) < 1, initial.sourceTop + ', ' + initial.connectionTop);
    check('the initial view is Not paired', initial.heading === 'Not paired', initial.heading);
    check('the preload bridge exists', initial.hasBridge === true);
    check('the bridge object is frozen', initial.bridgeFrozen === true);
    check('Node.js require is absent', initial.hasRequire === false);
    check('the Node.js process object is absent', initial.hasProcess === false);
    check('ipcRenderer is not exposed', initial.hasIpcRenderer === false);
    check('the page is labeled simulated', initial.demoText === true);
    check('the demo banner is visible', initial.bannerVisible === true);
    check('the demo pill is visible', initial.pillVisible === true);
    check('the demo line is visible', initial.demoLineVisible === true);
    check('the CSP meta tag is present', initial.csp.indexOf("default-src 'none'") !== -1);
    check('the platform label is local', initial.platform.indexOf('demo') !== -1, initial.platform);
    check('the native menu bar is visible', mainWindow.isMenuBarVisible() === true);
    check('all page resources are local files', initial.resources.every((url) => url.startsWith('file:')), initial.resources);
    check('the initial theme is light or dark', initial.theme === 'light' || initial.theme === 'dark', initial.theme);

    const menuLabels = Menu.getApplicationMenu().items.map((item) => item.label);
    check('the native menu has File, Edit, View, Window, and Help', ['File', 'Edit', 'View', 'Window', 'Help'].every((label) => menuLabels.includes(label)), menuLabels);

    await evaluate('window.hotspotshade.pair()');
    await wait(5000);
    const pairState = await evaluate('window.hotspotshade.pairState().then((result) => result.data)');
    check('the simulated pairing completes', pairState.state === 'paired', pairState.state);
    const pairedStatus = await evaluate('window.hotspotshade.status().then((result) => result.data)');
    check('the status reports a paired source device', pairedStatus.paired === true);
    check('the status stays labeled simulated', pairedStatus.demo === true);
    check('the engine boundary stays disconnected', pairedStatus.engine.boundary === 'not_connected');
    await wait(1300);
    const readyHeading = await evaluate("document.getElementById('dashboardTitle').textContent");
    check('the dashboard shows Ready', readyHeading === 'Ready', readyHeading);

    await evaluate('window.hotspotshade.start({ ping: true })');
    await wait(1600);
    const runningStatus = await evaluate('window.hotspotshade.status().then((result) => result.data)');
    check('the simulated tunnel reports running', runningStatus.running === true);
    check('the simulated ping setting is on', runningStatus.icmp_enabled === true);
    await wait(1200);
    const runningView = await evaluate(`(() => ({
      heading: document.getElementById('dashboardTitle').textContent,
      details: document.getElementById('connectionDetails').textContent
    }))()`);
    check('the dashboard shows On', runningView.heading === 'On', runningView.heading);
    check('the connection card shows simulated ping', runningView.details.indexOf('Ping is on.') !== -1, runningView.details);

    await evaluate('window.hotspotshade.stop()');
    await wait(1000);
    const stoppedStatus = await evaluate('window.hotspotshade.status().then((result) => result.data)');
    check('the simulated tunnel stops', stoppedStatus.running === false);
    check('the stop leaves a plain last stop message', typeof stoppedStatus.last_stop_message === 'string' && stoppedStatus.last_stop_message.length > 0, stoppedStatus.last_stop_message);

    await evaluate("document.querySelector('.nav-item[data-view=\"activity\"]').click()");
    await wait(700);
    const activity = await evaluate(`(() => ({
      visible: !document.getElementById('view-activity').hidden,
      rows: document.querySelectorAll('#activityList .activity-row').length,
      empty: !document.getElementById('activityState').hidden
    }))()`);
    check('the Activity view opens', activity.visible === true);
    check('the Activity view lists simulated entries', activity.rows > 0, activity.rows);
    check('the Activity empty state is not shown', activity.empty === false);

    await evaluate("document.getElementById('settingsNav').click()");
    await wait(200);
    await evaluate("document.getElementById('settingsTabPairing').click()");
    const pairingText = await evaluate("document.getElementById('settingsPairingState').textContent");
    check('Settings reports the simulated pairing', pairingText === 'Paired', pairingText);

    await evaluate("document.getElementById('settingsTabAdvanced').click()");
    await wait(500);
    await evaluate("document.getElementById('failuresRefresh').click()");
    await wait(600);
    const failures = await evaluate(`(() => ({
      rows: document.querySelectorAll('#failuresBody tr').length,
      summary: document.getElementById('failuresSummary').textContent,
      simulated: document.body.textContent.includes('Demo mode. Data is simulated.')
    }))()`);
    check('the failures table lists simulated groups', failures.rows >= 3, failures.rows);
    check('the failures summary is labeled simulated', failures.summary.indexOf('Simulated data.') !== -1, failures.summary);
    check('the settings view stays labeled simulated', failures.simulated === true);

    const beforeTheme = await evaluate("document.documentElement.getAttribute('data-theme')");
    await evaluate("document.getElementById('themeToggle').click()");
    const afterTheme = await evaluate("document.documentElement.getAttribute('data-theme')");
    check('the appearance toggle changes the theme', beforeTheme !== afterTheme, beforeTheme + ' -> ' + afterTheme);

    const copyCode = await evaluate(`window.hotspotshade.copyText('x'.repeat(20001)).then((result) => (result.ok === false ? result.error.code : 'ok'))`);
    check('oversized clipboard text is refused', copyCode === 'invalid_input', copyCode);

    const beforeUrl = mainWindow.webContents.getURL();
    try {
      await evaluate("try { location.href = 'https://example.com/'; } catch (error) {}");
    } catch (error) {
      /* A blocked navigation can reject the script. */
    }
    await wait(500);
    check('external navigation is blocked', mainWindow.webContents.getURL() === beforeUrl, mainWindow.webContents.getURL());

    const windowCountBefore = createdWindows.length;
    try {
      await evaluate("try { window.open('https://example.com/'); } catch (error) {}");
    } catch (error) {
      /* A blocked popup can reject the script. */
    }
    await wait(500);
    check('no second window is created', createdWindows.length === windowCountBefore, createdWindows.length);
    check('the page did not request an external resource', deniedRequests.length === 0, deniedRequests.slice(0, 3));
    const unexpectedErrors = pageErrors.filter((message) => message.indexOf('example.com') === -1);
    check('the page has no console errors', unexpectedErrors.length === 0, unexpectedErrors.slice(0, 5));

    const failed = results.filter((item) => !item.ok);
    finish(failed.length === 0);
  } catch (error) {
    check('the smoke test finished', false, error && error.stack ? error.stack : String(error));
    finish(false);
  }
});
