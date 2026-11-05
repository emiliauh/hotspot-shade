'use strict';

/* Axe-style accessibility check for the Linux page.
 *
 * Run on Linux with a display:
 *   xvfb-run -a npm run test:a11y
 *
 * The harness loads the normal sandboxed page with the demo backend. It checks
 * the dashboard, pairing, activity, the Settings sections, the dark theme, and
 * the high contrast token layer. It uses the in-tree rules in a11y-rules.mjs.
 * It is not a full axe-core run.
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
const { createAutostart } = require('../src/main/autostart');
const { createSettingsStore } = require('../src/main/settings');
const { evaluateSnapshot } = require('./a11y-rules.mjs');

const APP_ROOT = path.join(__dirname, '..');
const RENDERER_ROOT = path.join(APP_ROOT, 'src', 'renderer');
const PRELOAD_PATH = path.join(APP_ROOT, 'src', 'main', 'preload.js');
const ICON_PATH = path.join(APP_ROOT, 'assets', 'icon.png');
const INDEX_URL = pathToFileURL(path.join(RENDERER_ROOT, 'index.html')).href;
const USER_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-linux-a11y-'));

let mainWindow = null;
let unregisterIpc = null;
let backend = null;
let boundary = null;
let settingsStore = null;
const results = [];
const states = [];

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function evaluate(source) {
  return mainWindow.webContents.executeJavaScript(source, true);
}

const SNAPSHOT_SOURCE = `(() => {
  function visible(element) {
    if (!element) return false;
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
  }
  function selectorFor(element) {
    if (!element) return '';
    if (element.id) return '#' + element.id;
    const name = element.tagName.toLowerCase();
    if (element.classList && element.classList.length) return name + '.' + element.classList[0];
    const parent = element.parentElement;
    if (parent && parent.id) return '#' + parent.id + ' > ' + name;
    return name;
  }
  function nameFor(element) {
    const label = element.getAttribute('aria-label');
    if (label && label.trim()) return label.trim();
    const text = (element.textContent || '').replace(/\\s+/g, ' ').trim();
    if (text) return text;
    const title = element.getAttribute('title');
    return title ? title.trim() : '';
  }
  function backgroundFor(element) {
    let node = element;
    while (node && node.nodeType === 1) {
      const color = getComputedStyle(node).backgroundColor;
      if (color && color !== 'rgba(0, 0, 0, 0)' && color !== 'transparent') return color;
      node = node.parentElement;
    }
    return 'rgb(255, 255, 255)';
  }
  function focusableInside(element) {
    return !!element.querySelector('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])');
  }
  const buttons = Array.from(document.querySelectorAll('button')).filter(visible).map((element) => {
    const rect = element.getBoundingClientRect();
    return { selector: selectorFor(element), name: nameFor(element), width: rect.width, height: rect.height, hidden: false };
  });
  const links = Array.from(document.querySelectorAll('a[href]')).filter(visible).map((element) => ({
    selector: selectorFor(element), name: nameFor(element)
  }));
  const fields = Array.from(document.querySelectorAll('input, select, textarea')).filter(visible).map((element) => ({
    selector: selectorFor(element),
    hasLabel: !!((element.labels && element.labels.length) || element.getAttribute('aria-label') || element.getAttribute('aria-labelledby') || element.getAttribute('title'))
  }));
  const roles = Array.from(document.querySelectorAll('[role]')).filter(visible).map((element) => ({
    selector: selectorFor(element), role: (element.getAttribute('role') || '').trim()
  }));
  const ariaStates = [];
  for (const name of ['aria-pressed', 'aria-selected', 'aria-expanded', 'aria-checked']) {
    for (const element of Array.from(document.querySelectorAll('[' + name + ']'))) {
      if (!visible(element)) continue;
      ariaStates.push({ selector: selectorFor(element), name, value: element.getAttribute(name) });
    }
  }
  const tabindexes = Array.from(document.querySelectorAll('[tabindex]')).filter(visible).map((element) => ({
    selector: selectorFor(element), value: element.getAttribute('tabindex')
  }));
  const headings = Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6')).filter(visible).map((element) => ({
    selector: selectorFor(element), level: Number(element.tagName.slice(1))
  }));
  const lists = Array.from(document.querySelectorAll('ul, ol')).filter(visible).map((element) => ({
    selector: selectorFor(element),
    children: Array.from(element.children).map((child) => child.tagName.toLowerCase())
  }));
  const tables = Array.from(document.querySelectorAll('table')).filter(visible).map((element) => {
    const headers = Array.from(element.querySelectorAll('th'));
    return {
      selector: selectorFor(element),
      visible: true,
      headerCount: headers.length,
      scopedHeaders: headers.filter((header) => header.getAttribute('scope')).length
    };
  });
  const images = Array.from(document.querySelectorAll('img')).filter(visible).map((element) => ({
    selector: selectorFor(element),
    alt: element.getAttribute('alt') || '',
    decorative: element.getAttribute('aria-hidden') === 'true'
  }));
  const scrollRegions = Array.from(document.querySelectorAll('*')).filter((element) => {
    if (!visible(element)) return false;
    const style = getComputedStyle(element);
    if (!/(auto|scroll)/.test(style.overflowY + style.overflowX)) return false;
    return element.scrollHeight > element.clientHeight + 4 || element.scrollWidth > element.clientWidth + 4;
  }).map((element) => ({
    selector: selectorFor(element), tabindex: Number(element.getAttribute('tabindex') || 0)
  }));
  const ariaHiddenFocus = Array.from(document.querySelectorAll('[aria-hidden="true"]')).filter(visible).map((element) => ({
    selector: selectorFor(element), focusable: focusableInside(element)
  }));
  const landmarkSelectors = ['main', 'nav', 'header', 'footer', 'aside', '[role="main"]', '[role="navigation"]', '[role="banner"]', '[role="contentinfo"]', '[role="region"]'];
  const seenLandmarks = new Set();
  const landmarks = [];
  for (const selector of landmarkSelectors) {
    for (const element of Array.from(document.querySelectorAll(selector))) {
      if (seenLandmarks.has(element) || !visible(element)) continue;
      seenLandmarks.add(element);
      landmarks.push({ selector: selectorFor(element), label: element.getAttribute('aria-label') || element.getAttribute('aria-labelledby') || '' });
    }
  }
  const contrastSelectors = [
    'body', '.hero-title', '.hero-subtitle', '.card-title', '.card-value', '.detail-list li',
    '.setting-label', '.setting-help', '.body-copy', '.note', '.nav-label', '.brand-name',
    '.button-primary', '.button-secondary', '.button-danger', '.settings-tab[aria-selected="true"]',
    '.segment[aria-pressed="true"]', '.pill', '.activity-message', '.activity-time',
    '.failures-table th', '.failures-table td', '.empty-state', '.pairing-message', '.pair-code-value'
  ];
  const contrast = [];
  const seenContrast = new Set();
  for (const selector of contrastSelectors) {
    for (const element of Array.from(document.querySelectorAll(selector))) {
      if (!visible(element)) continue;
      const style = getComputedStyle(element);
      const size = parseFloat(style.fontSize);
      const weight = Number(style.fontWeight) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const key = selector;
      if (seenContrast.has(key)) continue;
      seenContrast.add(key);
      contrast.push({
        selector,
        color: style.color,
        background: backgroundFor(element),
        large
      });
    }
  }
  return {
    lang: document.documentElement.getAttribute('lang') || '',
    title: document.title,
    mainCount: document.querySelectorAll('main, [role="main"]').length,
    landmarks,
    buttons,
    links,
    fields,
    ids: Array.from(document.querySelectorAll('[id]')).map((element) => element.id),
    roles,
    ariaStates,
    tabindexes,
    headings,
    lists,
    tables,
    images,
    scrollRegions,
    ariaHiddenFocus,
    contrast,
    focusVisible: []
  };
})()`;

async function snapshot() {
  return evaluate(SNAPSHOT_SOURCE);
}

async function checkState(name) {
  const page = await snapshot();
  const violations = evaluateSnapshot(page);
  states.push({ name, violations: violations.length, checks: page.buttons.length + page.links.length + page.fields.length });
  for (const item of violations) {
    results.push({ state: name, id: item.id, message: item.message, target: item.target });
  }
}

async function keyboardFocus() {
  const seen = [];
  mainWindow.focus();
  mainWindow.webContents.focus();
  await wait(100);
  for (let index = 0; index < 8; index += 1) {
    mainWindow.webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Tab' });
    mainWindow.webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Tab' });
    await wait(60);
    const value = await evaluate(`(() => {
      const element = document.activeElement;
      if (!element || element === document.body) return null;
      const style = getComputedStyle(element);
      return {
        tag: element.tagName,
        selector: element.id ? '#' + element.id : element.tagName.toLowerCase(),
        outlineStyle: style.outlineStyle,
        outlineWidth: style.outlineWidth
      };
    })()`);
    if (value && !seen.some((item) => item.selector === value.selector)) seen.push(value);
  }
  return seen;
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

function finish() {
  const failed = results.length > 0;
  const report = {
    ok: !failed,
    electron: process.versions.electron,
    states,
    violations: results
  };
  console.log(JSON.stringify(report, null, 2));
  cleanup();
  app.exit(failed ? 1 : 0);
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
    settingsStore = createSettingsStore({
      filePath: path.join(USER_DATA, 'settings.json'),
      autostart: createAutostart({ env: { HS_AUTOSTART_DIR: path.join(USER_DATA, 'autostart') }, execPath: process.execPath }),
      notificationsSupported: true
    });

    const router = createRouter({
      backend: backend,
      boundary: boundary,
      clipboard: clipboard,
      settings: settingsStore,
      openSettings: function () { throw new Error('The Settings window is not used in this check.'); },
      appInfo: { version: app.getVersion(), platform: process.platform, arch: process.arch }
    });
    applySessionPolicy(session.defaultSession, { rendererRoot: RENDERER_ROOT });
    unregisterIpc = registerIpc({
      ipcMain: ipcMain,
      router: router,
      indexUrl: INDEX_URL,
      getWindows: function () { return [mainWindow]; }
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
      sendCommand: function (command) {
        sendMenuCommand({ window: mainWindow, command: command });
      },
      showAbout: function () {}
    }));

    mainWindow.webContents.on('console-message', function () {
      /* The page writes no error in this state set. */
    });

    await new Promise((resolve, reject) => {
      mainWindow.webContents.once('did-finish-load', resolve);
      mainWindow.webContents.once('did-fail-load', (_event, code, description) => {
        reject(new Error('The page did not load: ' + description + ' (' + code + ')'));
      });
    });
    await wait(1400);

    await checkState('dashboard');

    await evaluate("document.getElementById('primaryAction').click()");
    await wait(1300);
    await checkState('pairing');
    await evaluate("document.getElementById('cancelPairing').click()");
    await wait(300);

    await evaluate("document.querySelector('.nav-item[data-view=\"activity\"]').click()");
    await wait(600);
    await checkState('activity');
    await evaluate("document.querySelector('.nav-item[data-view=\"dashboard\"]').click()");
    await wait(200);

    await evaluate("document.getElementById('settingsNav').click()");
    await wait(700);
    await evaluate("document.getElementById('settingsTabGeneral').click()");
    await wait(200);
    await checkState('settings-general');

    await evaluate("document.getElementById('settingsTabPairing').click()");
    await wait(200);
    await checkState('settings-pairing');

    await evaluate("document.getElementById('settingsTabAdvanced').click()");
    await wait(700);
    await checkState('settings-advanced');

    await evaluate("document.querySelector('[data-theme-pref=\"dark\"]').click()");
    await wait(250);
    await checkState('settings-advanced-dark');

    await evaluate("document.documentElement.setAttribute('data-contrast', 'high')");
    await wait(150);
    await checkState('settings-advanced-high-contrast');
    await evaluate("document.documentElement.setAttribute('data-contrast', 'normal')");
    await evaluate("document.querySelector('[data-theme-pref=\"light\"]').click()");
    await wait(200);

    await evaluate("document.documentElement.setAttribute('data-window', 'settings')");
    await wait(150);
    const settingsWindowLayout = await evaluate(`(() => ({
      sidebar: getComputedStyle(document.querySelector('.sidebar')).display,
      grid: getComputedStyle(document.querySelector('.app-shell')).gridTemplateColumns
    }))()`);
    if (settingsWindowLayout.sidebar !== 'none') {
      results.push({ state: 'settings-window', id: 'settings-window-layout', message: 'The sidebar is visible in the Settings window.', target: '.sidebar' });
    }
    await checkState('settings-window');
    await evaluate("document.documentElement.setAttribute('data-window', 'main')");

    const focus = await keyboardFocus();
    const named = focus.filter((item) => item.tag);
    if (named.length < 2) {
      results.push({ state: 'keyboard', id: 'focus-visible', message: 'Keyboard focus did not reach two controls.', target: 'body' });
    }
    for (const item of named) {
      if (item.outlineStyle === 'none' || parseFloat(item.outlineWidth) < 2) {
        results.push({ state: 'keyboard', id: 'focus-visible', message: 'A keyboard focus ring is missing.', target: item.selector });
      }
    }
    states.push({ name: 'keyboard', focus: named.length });

    finish();
  } catch (error) {
    results.push({ state: 'harness', id: 'harness', message: error && error.message ? error.message : 'unknown error', target: '' });
    finish();
  }
});
