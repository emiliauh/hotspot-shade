'use strict';

/* Linux-only launch test for the real app entry point.
 *
 * Run with Xvfb and the real engine:
 *
 *   HOTSPOTSHADE_ENGINE=/abs/path/hotspotshade HOTSPOTSHADE_ENGINE_DEMO=1 \
 *     xvfb-run -a npx electron test/main-engine-launch.js
 *
 * This file loads src/main/main.js, which selects the engine backend from the
 * environment. It waits for the page, closes the window, and records whether
 * the app stopped the engine child with its normal quit path. It writes the
 * result to /tmp/hotspotshade-main-engine-report.json.
 *
 * The test uses the real main process. It does not change a route, create a
 * TUN device, or need root.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { app, dialog } = require('electron');

const REPORT_PATH = '/tmp/hotspotshade-main-engine-report.json';
const ENGINE_PATH = process.env.HOTSPOTSHADE_ENGINE || '';
const TEST_CRASH_WARNING = process.env.HS_TEST_DEMO_CRASH_WARNING === '1';
if (TEST_CRASH_WARNING && process.env.HOTSPOTSHADE_ENGINE_DEMO !== '1') {
  console.error('The crash-warning check requires the engine demo mode.');
  process.exit(2);
}
const warningDialogs = [];
if (TEST_CRASH_WARNING) {
  // Capture the real main entry's dialog call without blocking the test.
  dialog.showMessageBoxSync = (options) => { warningDialogs.push(options); return 0; };
}
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-main-engine-'));
app.setPath('userData', USER_DATA);
const checks = [];
let window = null;
let enginePidBefore = null;
let closeStarted = false;
let failed = false;

function check(name, condition, detail) {
  if (!condition) failed = true;
  checks.push({ name, ok: !!condition, detail: detail === undefined ? null : detail });
}

function engineChildren() {
  const found = [];
  let entries = [];
  try {
    entries = fs.readdirSync('/proc');
  } catch (error) {
    return found;
  }
  for (const entry of entries) {
    if (!/^[0-9]+$/.test(entry)) continue;
    let stat = '';
    let command = '';
    try {
      stat = fs.readFileSync('/proc/' + entry + '/stat', 'utf8');
      command = fs.readFileSync('/proc/' + entry + '/cmdline', 'utf8');
    } catch (error) {
      continue;
    }
    const close = stat.lastIndexOf(')');
    if (close === -1) continue;
    const fields = stat.slice(close + 2).split(' ');
    const parent = Number(fields[1]);
    if (parent !== process.pid) continue;
    if (command.split('\u0000').includes(ENGINE_PATH)) found.push(Number(entry));
  }
  return found;
}

function engineTempDirectories() {
  try {
    return fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith('hotspotshade-engine-'));
  } catch (error) {
    return [];
  }
}

function writeReport(reason) {
  const report = {
    ok: !failed,
    reason: reason,
    electron: process.versions.electron,
    node: process.versions.node,
    engine: ENGINE_PATH,
    engineDemo: process.env.HOTSPOTSHADE_ENGINE_DEMO === '1',
    checks: checks,
    engineChildrenAfter: engineChildren(),
    engineTempDirectoriesAfter: engineTempDirectories()
  };
  try {
    fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2));
  } catch (error) {
    /* The test runner reads the file. */
  }
}

app.on('browser-window-created', (_event, created) => {
  if (window) return;
  window = created;
  created.webContents.once('did-finish-load', async () => {
    try {
      const deadline = Date.now() + 15000;
      let heading = '';
      while (Date.now() < deadline) {
        heading = await created.webContents.executeJavaScript("document.getElementById('dashboardTitle').textContent", true);
        if (heading === 'Not paired') break;
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      const view = await created.webContents.executeJavaScript(`(() => ({
        heading: document.getElementById('dashboardTitle').textContent,
        pill: document.getElementById('demoPill').textContent,
        platform: document.getElementById('platformText').textContent,
        mode: document.getElementById('appMode').textContent,
        boundary: document.getElementById('appBoundary').textContent
      }))()`, true);
      check('the real main process starts the engine', view.heading === 'Not paired', view.heading);
      check('the real main process uses the engine labels', view.pill === 'Engine demo', view.pill);
      check('the real main process names the engine demo', view.platform.indexOf('engine demo') !== -1, view.platform);
      check('the real main process reports the engine mode', view.mode === 'Engine demo. Data is simulated.', view.mode);
      check('the real main process reports a connected engine', view.boundary === 'Connected', view.boundary);

      const children = engineChildren();
      enginePidBefore = children.length ? children[0] : null;
      check('one engine child process runs', children.length === 1, children);
      check('no engine temp directory is left before the close', engineTempDirectories().length <= 1, engineTempDirectories());
      if (TEST_CRASH_WARNING && children.length === 1) {
        // This child is the explicitly selected demo engine. It creates no
        // tunnel or route; the signal exercises an unexpected engine exit.
        process.kill(children[0], 'SIGKILL');
        const exitDeadline = Date.now() + 5000;
        while (engineChildren().length && Date.now() < exitDeadline) {
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
        check('the demo engine exits unexpectedly', engineChildren().length === 0);
        // Let the main process receive the child exit before requesting quit.
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    } catch (error) {
      check('the page check finished', false, error && error.stack ? error.stack : String(error));
    }
    closeStarted = true;
    app.quit();
  });
});

app.on('will-quit', () => {
  if (!closeStarted) {
    check('the window close path ran', false);
  } else {
    check('the engine child is gone after the close', engineChildren().length === 0, engineChildren());
    check('the engine temp directory is gone after the close', engineTempDirectories().length === 0, engineTempDirectories());
    check('the engine child was running before the close', Number.isInteger(enginePidBefore) && enginePidBefore > 0, enginePidBefore);
    if (TEST_CRASH_WARNING) {
      check('an unconfirmed cleanup displays one native warning',
        warningDialogs.length === 1 && warningDialogs[0].type === 'warning' &&
          warningDialogs[0].message === 'HotspotShade could not confirm that the engine cleaned up.' &&
          /Routes or rules may remain/.test(warningDialogs[0].detail),
        warningDialogs);
    }
  }
  writeReport('will-quit');
  if (failed) app.exit(1);
});

setTimeout(() => {
  if (!closeStarted) {
    check('the app opened a window in time', false, 'No window after 30 seconds.');
    writeReport('timeout');
    app.exit(1);
  }
}, 30000);

/* Load the real app entry point after the test listeners are in place. */
require('../src/main/main.js');
