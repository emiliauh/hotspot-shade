'use strict';

/* Process-tree memory measurement for the Linux demo shell.
 *
 * Run on Linux with a display, for example:
 *   xvfb-run -a npx electron test/memory-main.js
 *
 * The numbers include the main process, renderer, GPU, utility, and zygote
 * processes that Electron starts. RSS counts shared pages more than once. PSS
 * divides each shared page by the number of processes that map it, so it is the
 * better comparison value. Use either number for comparison, not as a precise
 * heap total.
 *
 * Set HS_MEMORY_FLAGS to a semicolon-separated list of Chromium switches to
 * test a candidate change against the same page and the same wait. Set
 * HS_MEMORY_DISABLE_HARDWARE to 1 to call app.disableHardwareAcceleration().
 * These controls exist for measurement only.
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
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-linux-memory-'));
const PROC_ROOT = '/proc';
const PAGE_SIZE_KB = readPageSizeKb();

const CANDIDATE_FLAGS = String(process.env.HS_MEMORY_FLAGS || '')
  .split(';')
  .map((value) => value.trim())
  .filter(Boolean);

let mainWindow = null;
let unregisterIpc = null;
let backend = null;
let boundary = null;

function applyCandidateFlags() {
  for (const flag of CANDIDATE_FLAGS) {
    const separator = flag.indexOf('=');
    if (separator === -1) app.commandLine.appendSwitch(flag);
    else app.commandLine.appendSwitch(flag.slice(0, separator), flag.slice(separator + 1));
  }
  if (process.env.HS_MEMORY_DISABLE_HARDWARE === '1') app.disableHardwareAcceleration();
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function readPageSizeKb() {
  try {
    const rollup = fs.readFileSync(path.join(PROC_ROOT, 'self', 'smaps_rollup'), 'utf8');
    const match = rollup.match(/^KernelPageSize:\s+(\d+)\s+kB$/m);
    if (match) return Number(match[1]);
  } catch (error) {
    /* Fall through to the common Linux page size. */
  }
  return 4;
}

async function evaluate(source) {
  return mainWindow.webContents.executeJavaScript(source, true);
}

function processRole(cmdline, pid) {
  if (cmdline.includes('--type=renderer')) return 'renderer';
  if (cmdline.includes('--type=gpu-process')) return 'gpu';
  if (cmdline.includes('--type=utility')) {
    if (cmdline.includes('network.mojom.NetworkService')) return 'network';
    if (cmdline.includes('audio.mojom.AudioService')) return 'audio';
    return 'utility';
  }
  if (cmdline.includes('--type=zygote')) return 'zygote';
  if (cmdline.includes('--type=crashpad-handler')) return 'crashpad';
  return pid === process.pid ? 'browser' : 'helper';
}

function readProcess(pid) {
  let stat = '';
  let cmdline = '';
  let rollup = '';
  try {
    stat = fs.readFileSync(path.join(PROC_ROOT, String(pid), 'stat'), 'utf8');
    cmdline = fs.readFileSync(path.join(PROC_ROOT, String(pid), 'cmdline'), 'utf8').replace(/\0/g, ' ');
    rollup = fs.readFileSync(path.join(PROC_ROOT, String(pid), 'smaps_rollup'), 'utf8');
  } catch (error) {
    return null;
  }
  const close = stat.lastIndexOf(')');
  if (close === -1) return null;
  const fields = stat.slice(close + 2).split(' ');
  const ppid = Number(fields[1]);
  const rssKb = Number(fields[21]) * PAGE_SIZE_KB;
  const pssField = rollup.match(/^Pss:\s+(\d+)\s+kB$/m);
  const privateField = rollup.match(/^Private_(?:Clean|Dirty):\s+(\d+)\s+kB$/gm) || [];
  const privateKb = privateField.reduce((total, line) => {
    const match = line.match(/(\d+)\s+kB/);
    return total + (match ? Number(match[1]) : 0);
  }, 0);
  return {
    pid: pid,
    ppid: ppid,
    role: processRole(cmdline, pid),
    rssKb: Number.isFinite(rssKb) ? rssKb : 0,
    pssKb: pssField ? Number(pssField[1]) : 0,
    privateKb: privateKb,
    command: cmdline.trim()
  };
}

function readProcessTable() {
  const rows = [];
  for (const entry of fs.readdirSync(PROC_ROOT)) {
    if (!/^\d+$/.test(entry)) continue;
    const row = readProcess(Number(entry));
    if (row) rows.push(row);
  }
  return rows;
}

function processTree() {
  const rows = readProcessTable();
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
  const members = rows.filter((row) => inTree.has(row.pid));
  const roles = {};
  for (const row of members) {
    const entry = roles[row.role] || { processCount: 0, rssKb: 0, pssKb: 0, privateKb: 0 };
    entry.processCount += 1;
    entry.rssKb += row.rssKb;
    entry.pssKb += row.pssKb;
    entry.privateKb += row.privateKb;
    roles[row.role] = entry;
  }
  return {
    processCount: members.length,
    rssKb: members.reduce((total, row) => total + row.rssKb, 0),
    pssKb: members.reduce((total, row) => total + row.pssKb, 0),
    privateKb: members.reduce((total, row) => total + row.privateKb, 0),
    roles: roles,
    processes: members.map((row) => ({
      pid: row.pid,
      ppid: row.ppid,
      role: row.role,
      rssKb: row.rssKb,
      pssKb: row.pssKb,
      privateKb: row.privateKb,
      command: row.command
    }))
  };
}

function appMetrics() {
  const metrics = app.getAppMetrics();
  const total = metrics.reduce((sum, metric) => {
    const memory = metric.memory || {};
    return sum + (Number(memory.workingSetSize) || 0);
  }, 0);
  return {
    processCount: metrics.length,
    workingSetKb: total,
    processes: metrics.map((metric) => ({
      pid: metric.pid,
      type: metric.type,
      workingSetKb: Number(metric.memory && metric.memory.workingSetSize) || 0
    }))
  };
}

function snapshot(label) {
  const tree = processTree();
  const metrics = appMetrics();
  return {
    label: label,
    at: new Date().toISOString(),
    treeRssKb: tree.rssKb,
    treePssKb: tree.pssKb,
    treePrivateKb: tree.privateKb,
    treeProcessCount: tree.processCount,
    roles: tree.roles,
    appMetricsWorkingSetKb: metrics.workingSetKb,
    appMetricsProcessCount: metrics.processCount,
    processes: tree.processes
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

applyCandidateFlags();
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

    await wait(5000);
    const idle = snapshot('idle dashboard, one-second status poll');

    await evaluate('window.hotspotshade.pair()');
    await wait(5000);
    await evaluate('window.hotspotshade.start({ ping: true })');
    await wait(1800);
    await evaluate("document.querySelector('.nav-item[data-view=\"activity\"]').click()");
    await wait(1000);
    await evaluate("document.getElementById('settingsNav').click()");
    await evaluate("document.getElementById('settingsTabAdvanced').click()");
    await wait(500);
    await evaluate("document.getElementById('failuresRefresh').click()");
    await wait(1200);
    const active = snapshot('active paired demo, activity opened, failures loaded');

    console.log(JSON.stringify({
      electron: process.versions.electron,
      chrome: process.versions.chrome,
      node: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      candidateFlags: CANDIDATE_FLAGS,
      disabledHardwareAcceleration: process.env.HS_MEMORY_DISABLE_HARDWARE === '1',
      idle: idle,
      active: active,
      deltaTreeRssKb: active.treeRssKb - idle.treeRssKb,
      deltaTreePssKb: active.treePssKb - idle.treePssKb,
      deltaWorkingSetKb: active.appMetricsWorkingSetKb - idle.appMetricsWorkingSetKb
    }, null, 2));

    cleanup();
    app.exit(0);
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    cleanup();
    app.exit(1);
  }
});
