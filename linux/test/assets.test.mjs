import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const channels = require('../src/main/channels.js');

function read(relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8');
}

function walk(directory) {
  const out = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

test('Electron is pinned to one exact version and has a lockfile entry', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.private, true);
  assert.equal(pkg.main, 'src/main/main.js');
  assert.equal(pkg.devDependencies.electron, '45.2.3');
  assert.match(pkg.devDependencies.electron, /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.devDependencies['@electron/packager'], '20.3.0');
  assert.match(pkg.devDependencies['@electron/packager'], /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.dependencies, undefined);

  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.lockfileVersion, 3);
  const electron = lock.packages['node_modules/electron'];
  assert.ok(electron, 'the lockfile has an Electron entry');
  assert.equal(electron.version, pkg.devDependencies.electron);
  assert.equal(electron.dev, true);
  assert.ok(electron.integrity);
  assert.match(electron.resolved, /^https:\/\/registry\.npmjs\.org\/electron\//);

  const packager = lock.packages['node_modules/@electron/packager'];
  assert.ok(packager, 'the lockfile has a packager entry');
  assert.equal(packager.version, pkg.devDependencies['@electron/packager']);
  assert.equal(packager.dev, true);
  assert.ok(packager.integrity);
});

test('the preload repeats the fixed channel and menu allowlists', () => {
  const preload = read('src/main/preload.js');
  for (const channel of Object.values(channels.IPC_CHANNELS)) {
    assert.ok(preload.includes("'" + channel + "'"), channel);
  }
  for (const command of channels.MENU_COMMANDS) {
    assert.ok(preload.includes("'" + command + "'"), command);
  }
  assert.match(preload, /contextBridge\.exposeInMainWorld\('hotspotshade'/);
  assert.doesNotMatch(preload, /exposeInMainWorld\('(ipcRenderer|require|process)'/);
  assert.doesNotMatch(preload, /require\('node:/);
  assert.doesNotMatch(preload, /\b(webUtils|shell|clipboard)\b/);
  assert.match(preload, /process\.argv/);
  assert.doesNotMatch(preload, /process\.(env|exit|binding|mainModule|cwd|chdir)/);
});

test('the page has a strict CSP and no inline script or style', () => {
  const html = read('src/renderer/index.html');
  const meta = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/);
  assert.ok(meta, 'the CSP meta tag exists');
  const policy = meta[1];
  assert.match(policy, /default-src 'none'/);
  assert.match(policy, /script-src 'self'/);
  assert.match(policy, /style-src 'self'/);
  assert.match(policy, /connect-src 'none'/);
  assert.match(policy, /object-src 'none'/);
  assert.match(policy, /frame-src 'none'/);
  assert.match(policy, /base-uri 'none'/);
  assert.doesNotMatch(policy, /unsafe-inline/);
  assert.doesNotMatch(policy, /unsafe-eval/);
  assert.doesNotMatch(policy, /https?:/);

  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i);
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
  assert.doesNotMatch(html, /javascript:/i);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
  assert.match(html, /<meta name="color-scheme" content="light dark">/);
});

test('the page names no remote asset or endpoint', () => {
  const html = read('src/renderer/index.html');
  const css = read('src/renderer/styles.css');
  const app = read('src/renderer/app.js');
  const model = read('src/renderer/model.js');
  const boot = read('src/renderer/boot.js');

  for (const source of [html, css, app, model, boot]) {
    const value = source.replace(/http:\/\/www\.w3\.org\/2000\/svg/g, '');
    assert.doesNotMatch(value, /https?:\/\//i);
    assert.doesNotMatch(value, /\bfetch\s*\(/);
    assert.doesNotMatch(value, /\bXMLHttpRequest\b/);
    assert.doesNotMatch(value, /\bWebSocket\b/);
    assert.doesNotMatch(value, /\bsendBeacon\b/);
  }
  assert.doesNotMatch(css, /@import/);
  assert.doesNotMatch(css, /url\s*\(/);
  assert.doesNotMatch(css, /(linear|radial)-gradient/i);

  for (const match of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
    const value = match[1];
    if (value.startsWith('#')) continue;
    assert.doesNotMatch(value, /^[a-z]+:/i, value);
    assert.doesNotMatch(value, /^\/\//, value);
    assert.ok(fs.existsSync(path.join(root, 'src/renderer', value)), 'missing local asset: ' + value);
  }
});

test('each view is labeled as simulated', () => {
  const html = read('src/renderer/index.html');
  const dashboard = html.slice(html.indexOf('id="view-dashboard"'), html.indexOf('id="view-activity"'));
  const activity = html.slice(html.indexOf('id="view-activity"'), html.indexOf('id="view-settings"'));
  const settings = html.slice(html.indexOf('id="view-settings"'), html.indexOf('</main>'));
  assert.match(dashboard, /Demo mode\. Data is simulated\./);
  assert.match(dashboard, /This pairing is simulated\./);
  assert.match(activity, /simulated/i);
  assert.match(settings, /simulated/i);
  assert.match(html, /All data is simulated\. No tunnel, routes, or network traffic\./);
  assert.match(html, /This demo cannot start the tunnel\./);
});

test('the source tree has no shell, network, or unsafe Electron route', () => {
  const files = walk(path.join(root, 'src'));
  const engineTransport = path.join('src', 'backend', 'engine-client.js');
  for (const file of files) {
    const relative = path.relative(root, file);
    const text = fs.readFileSync(file, 'utf8');
    const processAllowed = relative === engineTransport;
    for (const forbidden of [
      'shell.openExternal',
      'openExternal(',
      'webviewTag: true',
      'nodeIntegration: true',
      'sandbox: false',
      'contextIsolation: false',
      'loadURL(',
      'execFile(',
      'shell: true',
      'XMLHttpRequest',
      'WebSocket',
      'sendBeacon'
    ]) {
      assert.ok(!text.includes(forbidden), relative + ': found ' + forbidden);
    }
    if (processAllowed) continue;
    for (const forbidden of [
      "require('node:child_process')",
      'require("node:child_process")',
      "require('node:net')",
      'require("node:net")',
      "require('node:http')",
      'require("node:http")',
      "require('node:https')",
      'require("node:https")',
      "require('node:dgram')",
      'require("node:dgram")',
      "require('node:tls')",
      'require("node:tls")',
      'child_process',
      'spawn('
    ]) {
      assert.ok(!text.includes(forbidden), relative + ': found ' + forbidden);
    }
  }
  const transport = read(engineTransport);
  assert.match(transport, /127\.0\.0\.1/);
  assert.match(transport, /--token-fd/);
  assert.match(transport, /--parent-fd/);
  assert.doesNotMatch(transport, /shell:\s*true/);
  assert.doesNotMatch(transport, /exec(File)?\(/);
  assert.match(read('src/main/main.js'), /app\.enableSandbox\(\)/);
  assert.match(read('src/main/main.js'), /requestSingleInstanceLock\(\)/);
  assert.match(read('src/main/main.js'), /createDemoBackend/);
  assert.match(read('src/main/main.js'), /createEngineBoundary/);
  assert.match(read('src/main/main.js'), /resolveEngineConfig/);
  assert.match(read('src/main/security.js'), /onBeforeRequest/);
  assert.match(read('src/main/security.js'), /setPermissionRequestHandler/);
  assert.match(read('src/main/security.js'), /will-download/);
  assert.match(read('src/main/security.js'), /will-navigate/);
  assert.match(read('src/backend/engine-boundary.js'), /not connected/i);
});

test('no engine secret or transport name reaches the page or the preload', () => {
  for (const file of [
    'src/main/preload.js',
    'src/renderer/app.js',
    'src/renderer/model.js',
    'src/renderer/boot.js',
    'src/renderer/index.html'
  ]) {
    const text = read(file);
    assert.doesNotMatch(text, /HOTSPOTSHADE_ENGINE/, file);
    assert.doesNotMatch(text, /token-fd/, file);
    assert.doesNotMatch(text, /Authorization/, file);
    assert.doesNotMatch(text, /Bearer/, file);
  }
});

test('the app includes the accessibility and theme hooks', () => {
  const html = read('src/renderer/index.html');
  const css = read('src/renderer/styles.css');
  const app = read('src/renderer/app.js');
  assert.match(html, /class="skip-link"/);
  assert.match(html, /role="tablist"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /aria-pressed="false"/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /\[data-theme="dark"\]/);
  assert.match(css, /forced-colors/);
  assert.match(app, /ArrowRight/);
  assert.match(app, /prefers-color-scheme: dark/);
  assert.match(app, /scrollIntoView/);
});

test('the page exposes one fixed tunnel mode choice', () => {
  const html = read('src/renderer/index.html');
  const app = read('src/renderer/app.js');
  assert.match(html, /id="modePhone"[^>]*data-start-mode="phone"/);
  assert.match(html, /id="modeDirect"[^>]*data-start-mode="direct"/);
  assert.match(html, /aria-labelledby="modeChoiceLabel"/);
  assert.match(html, /id="modeHelp"/);
  assert.match(app, /call\('start', \{ mode: state\.startMode, ping: state\.ping \}\)/);
  assert.match(app, /model\.normalizeStartMode/);
  assert.match(app, /model\.startFailureText/);
  assert.match(app, /updateSetting\('tunnelMode', next\)/);
  assert.doesNotMatch(app, /call\('start',[^\n]*(iface|host|token|command|path)/);
});

test('the README documents the demo scope and the open work', () => {
  const readme = read('README.md');
  assert.match(readme, /Electron app sends both modes/i);
  assert.match(readme, /live hotspot, source device, and direct-mode\s+route test are still open/i);
  assert.match(readme, /Direct mode sends\s+`\{"mode":"tun","options":\{"ipv6":"block"\}\}`/);
  assert.match(readme, /packaged non-demo start, live direct routing, and route cleanup remain\s+unverified/i);
  assert.match(readme, /simulated/i);
  assert.match(readme, /engine boundary/i);
  assert.match(readme, /memory/i);
  assert.match(readme, /SPDX|Electron 45\.2\.3/);
});
