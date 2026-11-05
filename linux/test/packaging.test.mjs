import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { DEFAULT_ENGINE_PATH, DEFAULT_HELPER_PATH } = require('../src/backend/engine-client.js');

function read(relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8');
}

test('the polkit action points at the fixed helper path', () => {
  const policy = read('packaging/local.hotspotshade.tunnel.policy');
  assert.match(policy, /id="local\.hotspotshade\.tunnel"/);
  assert.match(policy, new RegExp('<annotate key="org\\.freedesktop\\.policykit\\.exec\\.path">' + DEFAULT_HELPER_PATH.replace(/\./g, '\\.') + '</annotate>'));
  assert.match(policy, /<allow_active>auth_admin_keep<\/allow_active>/);
  assert.doesNotMatch(policy, /allow_any>yes|allow_active>yes/);
});

test('the desktop entry starts only the packaged app', () => {
  const desktop = read('packaging/hotspotshade.desktop');
  assert.match(desktop, /^Name=HotspotShade$/m);
  assert.match(desktop, /^Exec=\/opt\/hotspotshade\/HotspotShade %U$/m);
  assert.match(desktop, /^Icon=hotspotshade$/m);
  assert.match(desktop, /^Terminal=false$/m);
  assert.doesNotMatch(desktop, /pkexec|hotspotshade-helper|token/i);
});

test('the package script builds the engine, the helper, and one .deb', () => {
  const script = read('scripts/package-deb.sh');
  assert.match(script, /cargo build --release --locked --manifest-path "\$repo\/rust\/Cargo\.toml"/);
  assert.match(script, /cargo build --release --locked --manifest-path "\$root\/helper\/Cargo\.toml"/);
  assert.match(script, /electron-packager/);
  assert.match(script, /dpkg-deb --build --root-owner-group/);
  assert.match(script, /uname -m/);
  assert.match(script, /Build the \$arch package on a \$arch host/);
  assert.match(script, /resources\/engine\/hotspotshade/);
  assert.match(script, /usr\/lib\/hotspotshade\/hotspotshade-helper/);
  assert.match(script, /local\.hotspotshade\.tunnel\.policy/);
  assert.doesNotMatch(script, /\bsudo\b/);
  assert.doesNotMatch(script, /curl|wget|\|\s*sh/);
});

test('the helper accepts no arguments and keeps the secret off the command line', () => {
  const source = read('helper/src/main.rs');
  const script = read('scripts/package-deb.sh');
  assert.match(source, /env::args_os\(\)\.len\(\) != 1/);
  assert.match(source, /"HS1"/);
  assert.match(source, /--token-fd/);
  assert.match(source, /--parent-fd/);
  assert.match(source, /DEFAULT_ENGINE/);
  assert.match(source, /PKEXEC_UID/);
  assert.match(source, /ENGINE_HOME/);
  assert.match(script, /\/var\/lib\/hotspotshade/);
  assert.doesNotMatch(source, /println!\([^)]*secret/i);
  assert.doesNotMatch(source, /eprintln!\([^)]*secret/i);
  assert.doesNotMatch(source, /Command::new\([^)]*arg\(/);
  assert.match(source, /command\.spawn/);
});

test('the helper and the transport use the same fixed paths', () => {
  const helper = read('helper/src/main.rs');
  const transport = read('src/backend/engine-client.js');
  assert.ok(helper.includes(DEFAULT_ENGINE_PATH));
  assert.ok(transport.includes(DEFAULT_HELPER_PATH));
  assert.ok(transport.includes(DEFAULT_ENGINE_PATH));
});
