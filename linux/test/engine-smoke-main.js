'use strict';

/* End-to-end Electron smoke test for the Linux engine backend.
 *
 * Run on Linux with Xvfb and the real HotspotShade binary:
 *
 *   HOTSPOTSHADE_ENGINE=/abs/path/hotspotshade HOTSPOTSHADE_ENGINE_DEMO=1 \
 *     xvfb-run -a npx electron test/engine-smoke-main.js
 *
 * The engine runs with its labeled demo backend. It creates no tunnel, route,
 * TUN device, or outer socket, and it needs no root. The test uses a temporary
 * Electron profile and the normal sandbox.
 *
 * This proves the Electron main process, the descriptor contract, the loopback
 * boundary, and the page status path against the real Rust engine. It does not
 * prove a Linux tunnel or a live hotspot.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, Menu, clipboard, ipcMain, session } = require('electron');

const { createEngineClient } = require('../src/backend/engine-client');
const { createEngineBackend } = require('../src/backend/engine-backend');
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
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-linux-engine-smoke-'));
const EXECUTABLE = process.env.HOTSPOTSHADE_ENGINE || '';
const ENGINE_DEMO = process.env.HOTSPOTSHADE_ENGINE_DEMO === '1';

const results = [];
const pageErrors = [];
const deniedRequests = [];
let mainWindow = null;
let unregisterIpc = null;
let client = null;
let backend = null;

function check(name, condition, detail) {
  results.push({ name: name, ok: !!condition, detail: detail === undefined ? null : detail });
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function evaluate(source) {
  return mainWindow.webContents.executeJavaScript(source, true);
}

async function waitFor(expression, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let value = null;
    try {
      value = await evaluate(expression);
    } catch (error) {
      value = null;
    }
    if (value) return value;
    await wait(200);
  }
  return null;
}

async function cleanup() {
  try {
    if (unregisterIpc) unregisterIpc();
    if (backend) await backend.dispose();
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

async function finish(ok, extra) {
  const report = {
    ok: ok,
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
    engineDemo: ENGINE_DEMO,
    checks: results,
    deniedRequests: deniedRequests.length,
    pageErrors: pageErrors,
    extra: extra || null
  };
  console.log(JSON.stringify(report, null, 2));
  await cleanup();
  app.exit(ok ? 0 : 1);
}

app.setPath('userData', USER_DATA);
app.enableSandbox();

app.whenReady().then(async () => {
  try {
    check('an engine binary is configured', !!EXECUTABLE, EXECUTABLE);
    check('the engine demo mode is requested', ENGINE_DEMO === true);
    if (!EXECUTABLE || !ENGINE_DEMO) {
      check('the test has the required settings', false, 'Set HOTSPOTSHADE_ENGINE and HOTSPOTSHADE_ENGINE_DEMO=1.');
      return finish(false);
    }

    client = createEngineClient({ executable: EXECUTABLE, demo: true, startTimeoutMs: 15000 });
    backend = createEngineBackend({ client: client });
    const settingsStore = createTestSettingsStore(USER_DATA);

    const router = createRouter({
      backend: backend,
      boundary: client,
      clipboard: clipboard,
      settings: settingsStore,
      openSettings: function () {
        sendMenuCommand({ window: mainWindow, command: 'settings-inline' });
      },
      appInfo: { version: app.getVersion(), platform: process.platform, arch: process.arch },
      onInternalError: function () {
        pageErrors.push('The engine backend request failed.');
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
    Menu.setApplicationMenu(buildApplicationMenu({
      Menu: Menu,
      app: app,
      window: mainWindow,
      engineMode: true,
      sendCommand: function (command) {
        sendMenuCommand({ window: mainWindow, command: command });
      },
      showAbout: function () {}
    }));

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
      if (message && level >= 3) pageErrors.push(message);
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

    const ready = await waitFor("document.getElementById('dashboardTitle').textContent === 'Not paired'", 12000);
    check('the real engine reports the initial state', ready === true);

    const initial = await evaluate(`(() => ({
      heading: document.getElementById('dashboardTitle').textContent,
      pill: document.getElementById('demoPill').textContent,
      banner: document.getElementById('demoBannerText').textContent,
      demoLine: document.getElementById('demoLine').textContent,
      platform: document.getElementById('platformText').textContent,
      mode: document.getElementById('appMode').textContent,
      boundary: document.getElementById('appBoundary').textContent,
      tunnel: document.getElementById('appTunnel').textContent,
      body: document.body.textContent
    }))()`);
    check('the engine mode is labeled', initial.pill === 'Engine demo', initial.pill);
    check('the banner says the engine is in demo mode', initial.banner.indexOf('local engine service runs in demo mode') !== -1, initial.banner);
    check('the hero says the engine demo is simulated', initial.demoLine.indexOf('Engine demo mode') !== -1, initial.demoLine);
    check('the platform pill names the engine demo', initial.platform.indexOf('engine demo') !== -1, initial.platform);
    check('App details name the engine demo', initial.mode === 'Engine demo. Data is simulated.', initial.mode);
    check('the engine boundary reports connected', initial.boundary === 'Connected', initial.boundary);
    check('the tunnel row does not claim a tunnel', initial.tunnel.indexOf('Engine demo') !== -1, initial.tunnel);

    const bootstrap = await evaluate('window.hotspotshade.bootstrap().then((result) => result.data)');
    check('bootstrap reports the engine backend', bootstrap.mode === 'engine', bootstrap.mode);
    check('bootstrap carries no secret or token', !/secret|token|identity/i.test(JSON.stringify(bootstrap)), Object.keys(bootstrap).join(','));

    const statusShape = await evaluate('window.hotspotshade.status().then((result) => result.data)');
    check('the real status has the engine shape', statusShape.demo === true && typeof statusShape.paired === 'boolean' && typeof statusShape.phone === 'object', JSON.stringify(statusShape).slice(0, 120));

    /* Cancel one pairing request through the page button. */
    await evaluate("document.getElementById('primaryAction').click()");
    await wait(1500);
    const pairingVisible = await evaluate("document.getElementById('pairingPanel').hidden === false");
    check('the pairing panel opens for the engine', pairingVisible === true);
    await evaluate("document.getElementById('cancelPairing').click()");
    await wait(800);
    const cancelled = await evaluate('window.hotspotshade.pairState().then((result) => result.data)');
    check('Cancel stops the engine pairing request', cancelled.state === 'idle', cancelled.state);

    /* Pair for real through the engine. The engine demo waits about 4 seconds. */
    await wait(600);
    await evaluate("document.getElementById('primaryAction').click()");
    const paired = await waitFor("window.hotspotshade.pairState().then((result) => result.data).then((pair) => pair.state === 'paired')", 12000);
    check('the engine pairing completes', paired === true);
    const pairedStatus = await evaluate('window.hotspotshade.status().then((result) => result.data)');
    check('the engine status reports a paired source device', pairedStatus.paired === true);
    check('the engine demo status stays labeled', pairedStatus.demo === true);

    /* The engine demo moves through source states. Wait for the Turn on action. */
    const turnOn = await waitFor("document.getElementById('primaryAction').dataset.action === 'turnOn'", 25000);
    check('the dashboard offers Turn on', turnOn === true);
    if (turnOn) {
      await evaluate("document.getElementById('primaryAction').click()");
    } else {
      await evaluate('window.hotspotshade.start({ ping: true })');
    }
    const running = await waitFor("window.hotspotshade.status().then((result) => result.data).then((status) => status.running === true)", 12000);
    check('Start reaches the engine and the tunnel state is on', running === true);
    await wait(1400);
    const onView = await evaluate(`(() => ({
      heading: document.getElementById('dashboardTitle').textContent,
      details: document.getElementById('connectionDetails').textContent
    }))()`);
    check('the dashboard shows On', onView.heading === 'On', onView.heading);
    check('the connection card shows the engine ping state', onView.details.indexOf('Ping is on.') !== -1, onView.details);

    /* Stop through the page action. */
    const turnOff = await waitFor("document.getElementById('primaryAction').dataset.action === 'turnOff'", 3000);
    check('the dashboard offers Turn off', turnOff === true);
    if (turnOff) await evaluate("document.getElementById('primaryAction').click()");
    else await evaluate('window.hotspotshade.stop()');
    const stopped = await waitFor("window.hotspotshade.status().then((result) => result.data).then((status) => status.running === false)", 12000);
    check('Stop reaches the engine and the tunnel state is off', stopped === true);
    const stoppedStatus = await evaluate('window.hotspotshade.status().then((result) => result.data)');
    check('the engine reports the stop reason', stoppedStatus.last_stop && stoppedStatus.last_stop.reason === 'user', JSON.stringify(stoppedStatus.last_stop));
    if (typeof stoppedStatus.last_stop_message === 'string' && stoppedStatus.last_stop_message) {
      await wait(1200);
      const stopView = await evaluate("document.getElementById('connectionDetails').textContent");
      check('the page shows the engine last stop message', stopView.indexOf(stoppedStatus.last_stop_message) !== -1, stopView);
    } else {
      check('the engine sends no stop message for a user stop', true, 'The engine sends a message for an automatic stop only.');
    }
    const modelLine = await evaluate("window.HotspotShadeModel.lastStopLine({ running: false, last_stop_message: 'The hotspot turned off, so HotspotShade turned the tunnel off.' })");
    check('the page can show an engine last stop message', modelLine === 'Last stop: The hotspot turned off, so HotspotShade turned the tunnel off.', modelLine);

    /* Forget through the page action. */
    await wait(500);
    const forgetAction = await evaluate("document.getElementById('secondaryAction').dataset.action");
    check('the dashboard offers Forget', forgetAction === 'forget', forgetAction);
    if (forgetAction === 'forget') await evaluate("document.getElementById('secondaryAction').click()");
    else await evaluate('window.hotspotshade.forget()');
    const forgotten = await waitFor("window.hotspotshade.status().then((result) => result.data).then((status) => status.paired === false && status.forget && (status.forget.state === 'confirmed' || status.forget.state === 'not_delivered'))", 8000);
    check('Forget reaches the engine', forgotten === true);

    const failures = await evaluate('window.hotspotshade.failures().then((result) => result.data)');
    check('the engine failure record has the fixed shape', failures && Array.isArray(failures.groups) && typeof failures.total === 'number', JSON.stringify(failures).slice(0, 100));
    check('the engine failure record is labeled simulated', failures.demo === true);

    const diagnostics = await evaluate('window.hotspotshade.diagnostics().then((result) => result.data)');
    check('the engine diagnostics have the fixed shape', diagnostics && typeof diagnostics.engine === 'object' && typeof diagnostics.setup === 'object', Object.keys(diagnostics || {}).join(','));

    /* Crash the engine. The page must show a plain stale warning, not a claim
     * that the tunnel still reports live data. */
    const pid = client.pid;
    check('the engine process id is known', Number.isInteger(pid) && pid > 0, pid);
    if (pid) process.kill(pid, 'SIGKILL');
    await wait(1500);
    const crashResult = await evaluate("window.hotspotshade.status().then((result) => result, (error) => ({ ok: false, error: { code: 'throw', message: String(error) } }))");
    check('the crash becomes a plain engine error', crashResult.ok === false && crashResult.error.code === 'engine_stopped', JSON.stringify(crashResult).slice(0, 160));
    check('the crash error has plain text', crashResult.ok === false && /^The engine stopped unexpectedly/.test(crashResult.error.message), crashResult.ok ? '' : crashResult.error.message);
    const stale = await waitFor("document.getElementById('attentionList').textContent.indexOf('The engine did not answer') !== -1", 6000);
    check('the page shows a stale status after the crash', stale === true);
    const noDemoFallback = await evaluate("document.getElementById('modeCardBody').textContent.indexOf('local engine service') !== -1");
    check('the page does not fall back to demo labels after the crash', noDemoFallback === true);

    check('the page requested no external resource', deniedRequests.length === 0, deniedRequests.slice(0, 3));
    check('the page has no console errors', pageErrors.length === 0, pageErrors.slice(0, 5));

    const failed = results.filter((item) => !item.ok);
    return finish(failed.length === 0, {
      engineExit: client.exitInfo(),
      tempDirectory: client.tempDirectory
    });
  } catch (error) {
    check('the engine smoke test finished', false, error && error.stack ? error.stack : String(error));
    return finish(false);
  }
});
