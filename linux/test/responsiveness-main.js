'use strict';

/* Responsiveness probe for the Linux demo shell.
 *
 * This file is not part of the normal test run. It compares the default
 * compositor path with a candidate Chromium switch list. It uses a temporary
 * profile and the normal sandbox.
 *
 *   xvfb-run -a npx electron test/responsiveness-main.js
 *   HS_MEMORY_FLAGS=disable-threaded-compositing xvfb-run -a npx electron test/responsiveness-main.js
 *
 * Set HS_SHOW_AFTER_LOAD=1 to call show() after did-finish-load. Use it to
 * separate a window lifecycle problem from a paint problem.
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
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-linux-responsive-'));

const CANDIDATE_FLAGS = String(process.env.HS_MEMORY_FLAGS || '')
  .split(';')
  .map((value) => value.trim())
  .filter(Boolean);
const SHOW_AFTER_LOAD = process.env.HS_SHOW_AFTER_LOAD === '1';

const STARTED_AT = process.hrtime.bigint();
let mainWindow = null;
let unregisterIpc = null;
let backend = null;
let boundary = null;

for (const flag of CANDIDATE_FLAGS) {
  const separator = flag.indexOf('=');
  if (separator === -1) app.commandLine.appendSwitch(flag);
  else app.commandLine.appendSwitch(flag.slice(0, separator), flag.slice(separator + 1));
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function evaluate(source) {
  return mainWindow.webContents.executeJavaScript(source, true);
}

function cpuTicksForTree() {
  const rows = [];
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const stat = fs.readFileSync('/proc/' + entry + '/stat', 'utf8');
      const close = stat.lastIndexOf(')');
      const fields = stat.slice(close + 2).split(' ');
      rows.push({
        pid: Number(entry),
        ppid: Number(fields[1]),
        ticks: Number(fields[11]) + Number(fields[12])
      });
    } catch (error) {
      /* The process ended. */
    }
  }
  const inTree = new Set([process.pid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const row of rows) {
      if (!inTree.has(row.pid) && inTree.has(row.ppid)) {
        inTree.add(row.pid);
        changed = true;
      }
    }
  }
  return rows.filter((row) => inTree.has(row.pid)).reduce((total, row) => total + row.ticks, 0);
}

function stats(samples) {
  const sorted = samples.slice().sort((left, right) => left - right);
  const mean = samples.reduce((total, value) => total + value, 0) / samples.length;
  const percentile = (fraction) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];
  return {
    count: samples.length,
    meanMs: Math.round(mean * 100) / 100,
    p50Ms: Math.round(percentile(0.5) * 100) / 100,
    p95Ms: Math.round(percentile(0.95) * 100) / 100,
    maxMs: Math.round(sorted[sorted.length - 1] * 100) / 100,
    over20Ms: samples.filter((value) => value > 20).length,
    over33Ms: samples.filter((value) => value > 33).length
  };
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
    let readyToShow = false;
    mainWindow.once('ready-to-show', function () {
      readyToShow = true;
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
    const loadMs = Number(process.hrtime.bigint() - STARTED_AT) / 1e6;
    if (SHOW_AFTER_LOAD && !mainWindow.isVisible()) mainWindow.show();
    await wait(1500);
    const visibility = {
      windowVisible: mainWindow.isVisible(),
      documentVisibility: await evaluate('document.visibilityState'),
      readyToShow: readyToShow
    };

    const wallBefore = process.hrtime.bigint();
    const cpuBefore = cpuTicksForTree();
    const idleFrames = await Promise.race([
      evaluate(`new Promise((resolve) => {
        const samples = [];
        let last = performance.now();
        let count = 0;
        function step(now) {
          samples.push(now - last);
          last = now;
          count += 1;
          if (count < 180) requestAnimationFrame(step);
          else resolve(samples);
        }
        requestAnimationFrame(step);
      })`),
      wait(5000).then(() => null)
    ]);
    const cpuAfter = cpuTicksForTree();
    const elapsedClock = Number(process.hrtime.bigint() - wallBefore) / 1e9;
    // Linux reports process time in USER_HZ. It is 100 on the supported hosts.
    const tickSeconds = 1 / 100;
    if (!idleFrames) {
      console.log(JSON.stringify({
        electron: process.versions.electron,
        chrome: process.versions.chrome,
        candidateFlags: CANDIDATE_FLAGS,
        showAfterLoad: SHOW_AFTER_LOAD,
        loadMs: Math.round(loadMs),
        visibility: visibility,
        idleFrames: null,
        note: 'No animation frame arrived in 5 seconds.'
      }, null, 2));
      cleanup();
      app.exit(2);
      return;
    }

    await evaluate("document.querySelector('.nav-item[data-view=\"activity\"]').click()");
    await wait(600);
    await evaluate(`(() => {
      const list = document.getElementById('activityList');
      const state = document.getElementById('activityState');
      list.hidden = false;
      state.hidden = true;
      list.textContent = '';
      for (let index = 0; index < 120; index += 1) {
        const row = document.createElement('li');
        row.className = 'activity-row';
        const time = document.createElement('span');
        time.className = 'activity-time';
        time.textContent = '00:00';
        const message = document.createElement('p');
        message.className = 'activity-message';
        message.textContent = 'Synthetic probe row ' + index;
        row.appendChild(time);
        row.appendChild(message);
        list.appendChild(row);
      }
      return true;
    })()`);
    await wait(400);

    const scrollFrames = await Promise.race([
      evaluate(`new Promise((resolve) => {
        const list = document.getElementById('activityList');
        const samples = [];
        let last = performance.now();
        let count = 0;
        function step(now) {
          samples.push(now - last);
          last = now;
          count += 1;
          const max = Math.max(0, list.scrollHeight - list.clientHeight);
          list.scrollTop = (count / 180) * max;
          if (count < 180) requestAnimationFrame(step);
          else resolve(samples);
        }
        requestAnimationFrame(step);
      })`),
      wait(5000).then(() => null)
    ]);

    const clickLatency = await Promise.race([
      evaluate(`new Promise((resolve) => {
        const items = Array.prototype.slice.call(document.querySelectorAll('.nav-item[data-view]'));
        const samples = [];
        let index = 0;
        function next() {
          if (index >= 24) {
            resolve(samples);
            return;
          }
          const target = items[index % items.length];
          const start = performance.now();
          target.click();
          index += 1;
          requestAnimationFrame(() => {
            samples.push(performance.now() - start);
            next();
          });
        }
        next();
      })`),
      wait(5000).then(() => null)
    ]);

    console.log(JSON.stringify({
      electron: process.versions.electron,
      chrome: process.versions.chrome,
      candidateFlags: CANDIDATE_FLAGS,
      showAfterLoad: SHOW_AFTER_LOAD,
      loadMs: Math.round(loadMs),
      visibility: visibility,
      idleFrames: stats(idleFrames),
      scrollFrames: scrollFrames ? stats(scrollFrames) : null,
      clickLatency: clickLatency ? stats(clickLatency) : null,
      treeCpuPercentDuringFrameSample: Math.round(((cpuAfter - cpuBefore) * tickSeconds / elapsedClock) * 1000) / 10
    }, null, 2));

    cleanup();
    app.exit(0);
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    cleanup();
    app.exit(1);
  }
});
