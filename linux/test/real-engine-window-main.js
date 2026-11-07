'use strict';

// Run only in a disposable, network-isolated Linux environment. This opens the
// real window against a non-demo user engine and never requests a tunnel.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, clipboard, ipcMain, session } = require('electron');
const { createEngineClient } = require('../src/backend/engine-client');
const { createEngineBackend } = require('../src/backend/engine-backend');
const { createRouter, registerIpc } = require('../src/main/ipc');
const { applySessionPolicy, hardenWebContents } = require('../src/main/security');
const { createMainWindow } = require('../src/main/window');
const { createTestSettingsStore } = require('./fixtures/test-settings');

if (process.platform !== 'linux' || process.env.HS_TEST_NETWORK_CONFINED !== '1' ||
    !path.isAbsolute(process.env.HS_REAL_ENGINE_BIN || '') || process.getuid() === 0) {
  console.error('Use a non-root, network-isolated Linux environment and HS_REAL_ENGINE_BIN.');
  process.exit(2);
}

const root = path.join(__dirname, '..');
const renderer = path.join(root, 'src', 'renderer');
const indexUrl = pathToFileURL(path.join(renderer, 'index.html')).href;
const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-real-window-'));
app.setPath('userData', userData);
app.enableSandbox();

app.whenReady().then(async () => {
  let client;
  let backend;
  let window;
  let unregister;
  let ok = false;
  try {
    client = createEngineClient({ executable: process.env.HS_REAL_ENGINE_BIN, demo: false, startTimeoutMs: 15000 });
    backend = createEngineBackend({ client });
    await client.start();
    const router = createRouter({
      backend, boundary: client, clipboard,
      settings: createTestSettingsStore(userData),
      openSettings: function () {},
      appInfo: { version: app.getVersion(), platform: process.platform, arch: process.arch }
    });
    applySessionPolicy(session.defaultSession, { rendererRoot: renderer });
    unregister = registerIpc({ ipcMain, router, indexUrl, getWindow: () => window });
    window = createMainWindow({
      BrowserWindow, appRoot: renderer,
      preloadPath: path.join(root, 'src', 'main', 'preload.js'),
      iconPath: path.join(root, 'assets', 'icon.png')
    });
    hardenWebContents(window.webContents, { indexUrl });
    await new Promise((resolve, reject) => {
      window.webContents.once('did-finish-load', resolve);
      window.webContents.once('did-fail-load', (_event, code) => reject(new Error('Page load failed: ' + code)));
    });
    const deadline = Date.now() + 12000;
    let result;
    while (Date.now() < deadline) {
      result = await window.webContents.executeJavaScript(`(async () => {
        if (!window.hotspotshade) return null;
        const status = await window.hotspotshade.status();
        return {
          status,
          heading: document.getElementById('dashboardTitle').textContent,
          demoVisible: !document.getElementById('demoPill').hidden
        };
      })()`);
      if (result && result.status && result.status.ok && result.status.data &&
          result.status.data.demo === false &&
          ['Not paired', 'Waiting for your source device'].includes(result.heading) &&
          !result.demoVisible) break;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (!result || !result.status || !result.status.ok || !result.status.data ||
        result.status.data.demo !== false || result.status.data.running !== false ||
        result.status.data.paired !== false ||
        !['Not paired', 'Waiting for your source device'].includes(result.heading) || result.demoVisible) {
      const data = result && result.status && result.status.data || {};
      throw new Error('Real-engine status was not rendered as expected: ' + JSON.stringify({
        ok: !!(result && result.status && result.status.ok),
        demo: data.demo, running: data.running, paired: data.paired,
        heading: result && result.heading, demoVisible: result && result.demoVisible
      }));
    }
    console.log('REAL_ENGINE_WINDOW_OK');
    ok = true;
  } catch (error) {
    console.error('Real engine window check failed:', error && error.message);
  } finally {
    if (unregister) unregister();
    if (backend) {
      const stop = await backend.dispose();
      if (!stop || !stop.stopped || (client && client.isRunning())) {
        console.error('The engine did not stop cleanly.');
        ok = false;
      }
    }
    if (window && !window.isDestroyed()) window.destroy();
    fs.rmSync(userData, { recursive: true, force: true });
    app.exit(ok ? 0 : 1);
  }
}).catch((error) => {
  console.error('Real engine window setup failed:', error && error.message);
  app.exit(1);
});
