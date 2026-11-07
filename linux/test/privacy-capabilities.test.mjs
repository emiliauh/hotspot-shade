import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const model = require('../src/renderer/model.js');

function read(relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8');
}

function mode(view, id) {
  return view.modes.find((row) => row.id === id);
}

test('destination privacy reports a default build behavior, not a live mode', () => {
  const view = model.privacyView({ engine: true });
  assert.equal(view.mode, 'off');
  assert.equal(view.modeText, 'Off');
  assert.equal(view.modeState, 'default');
  assert.equal(view.modeStateText, 'Default');
  assert.equal(view.modePillText, 'Off (default)');
  assert.equal(view.appliesLiveMode, false);
  assert.equal(view.switchAvailable, false);
  assert.deepEqual(view.modes.map((row) => row.id), ['off', 'shape', 'hide', 'cover']);
  assert.equal(mode(view, 'off').state, 'default');
  assert.equal(mode(view, 'off').stateText, 'Default');
  assert.ok(view.modes.every((row) => row.state !== 'in_force'));
  for (const id of ['shape', 'hide']) {
    assert.equal(mode(view, id).state, 'unavailable', id);
    assert.equal(mode(view, id).stateText, 'Unavailable', id);
    assert.ok(mode(view, id).detail.length > 40, id + ' explains why it is unavailable');
  }
  assert.equal(mode(view, 'cover').state, 'deferred');
  assert.equal(mode(view, 'cover').stateText, 'Deferred');
  assert.match(mode(view, 'off').detail, /when a tunnel runs/);
  assert.match(mode(view, 'off').detail, /adds no concealment/);
  assert.match(mode(view, 'off').detail, /does not report whether a tunnel is running/);
});

test('the engine build reports no ECH, no server name override, and no DoH', () => {
  const view = model.privacyView({ engine: true });
  assert.deepEqual(view.facts.map((fact) => fact.id), ['ech', 'server_name', 'doh', 'one_socket']);
  for (const id of ['ech', 'server_name', 'doh']) {
    assert.equal(view.facts.find((fact) => fact.id === id).value, 'Not in this build', id);
  }
  assert.equal(view.facts.find((fact) => fact.id === 'one_socket').value, 'Yes');
  assert.match(view.facts.find((fact) => fact.id === 'ech').detail, /application can use its own ECH/i);
  assert.match(view.facts.find((fact) => fact.id === 'doh').detail, /resolver or application can use encrypted DNS/i);
  assert.equal(view.engine, true);
  assert.equal(view.demo, false);
});

test('the hide row states why the current relay design cannot provide it', () => {
  const view = model.privacyView({ engine: true });
  const detail = mode(view, 'hide').detail;
  assert.match(detail, /unavailable under the current design/i);
  assert.match(detail, /does not terminate another application TLS connection/i);
  assert.match(detail, /cannot add ECH or change the server name/i);
  assert.match(detail, /adding ECH or DoH to the engine would not by itself hide relayed application TLS/i);
  assert.match(detail, /offers no switch/i);
  assert.doesNotMatch(detail, /blocked on an unresolved/i);
  assert.doesNotMatch(detail, /until a client boundary is chosen/i);
  assert.doesNotMatch(detail, /approved/i);
});

test('the card states what may stay visible instead of claiming names are always seen', () => {
  const view = model.privacyView({ engine: true });
  assert.match(view.intro, /reports what the build can do/);
  assert.match(view.intro, /does not report whether a tunnel is running/);
  assert.match(view.intro, /adds no concealment/);
  assert.doesNotMatch(view.intro, /in force|running now/i);
  assert.match(view.storageNote, /saves no setting/);
  assert.match(view.storageNote, /stores no destination-privacy mode/);
  const text = view.limits.join(' ');
  assert.match(text, /adds no concealment/);
  assert.match(text, /may see the TLS server name/);
  assert.match(text, /An application or resolver can use its own ECH or encrypted DNS/);
  assert.match(text, /outside this app/);
  assert.match(text, /Metadata such as the destination address/);
  assert.match(text, /fingerprint/);
  assert.match(text, /volume patterns/);
  assert.match(text, /nested TLS/);
  assert.match(text, /Adding ECH and DoH to the engine would not by itself hide relayed application TLS/);
  assert.doesNotMatch(text, /can still see DNS names/i);
  assert.doesNotMatch(text, /carrier can still see/i);
});

test('demo mode labels the card as simulated and never claims a tunnel', () => {
  const view = model.privacyView({ demo: true, engine: false });
  assert.equal(view.demo, true);
  assert.match(view.intro, /^Demo mode\./);
  assert.match(view.intro, /simulated backend runs no tunnel/);
  assert.match(view.intro, /does not report a live mode/);
  assert.equal(mode(view, 'hide').state, 'unavailable');
  assert.equal(mode(view, 'cover').state, 'deferred');
});

test('malformed input cannot mark a mode available or live', () => {
  for (const input of [null, undefined, 'engine', 7, [], [{ demo: true }], { demo: 'true' }, { engine: 1 }]) {
    const view = model.privacyView(input);
    assert.equal(view.mode, 'off');
    assert.equal(view.modeState, 'default');
    assert.equal(view.appliesLiveMode, false);
    assert.equal(view.switchAvailable, false);
    assert.equal(view.demo, false);
    assert.equal(view.engine, false);
    assert.equal(mode(view, 'shape').state, 'unavailable');
    assert.equal(mode(view, 'hide').state, 'unavailable');
    assert.equal(mode(view, 'cover').state, 'deferred');
  }
});

test('the report holds no address, host, token, or key', () => {
  const value = JSON.stringify(model.privacyView({ demo: true, engine: false }));
  assert.doesNotMatch(value, /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  assert.doesNotMatch(value, /:\/\//);
  assert.doesNotMatch(value, /token|secret|password|identity|@/i);
});

test('the page shows the privacy card as read-only and saves nothing', () => {
  const html = read('src/renderer/index.html');
  const app = read('src/renderer/app.js');
  const settings = read('src/main/preload.js');

  const card = html.slice(html.indexOf('id="privacyCard"'), html.indexOf('id="demoScenariosCard"'));
  assert.ok(card.includes('Destination privacy'));
  assert.ok(card.includes('id="privacyModes"'));
  assert.ok(card.includes('id="privacyFacts"'));
  assert.ok(card.includes('id="privacyLimits"'));
  assert.ok(card.includes('Off (default)'));
  assert.ok(card.includes('does not report a live mode'));
  assert.doesNotMatch(card, /<input|<select|<button/);
  assert.match(card, /read-only/i);

  assert.match(app, /model\.privacyView\(\{ demo: simulatedData\(\), engine: engineMode\(\) \}\)/);
  assert.match(app, /setText\(dom\.privacyModePill, view\.modePillText\)/);
  assert.doesNotMatch(app, /is off in this build/);
  assert.doesNotMatch(app, /updateSetting\(\s*'privacy'/);
  assert.doesNotMatch(app, /localStorage[^\n]*privacy/i);
  assert.doesNotMatch(settings, /privacy/i);
  assert.match(settings, /SETTING_NAMES = Object\.freeze\(\['notifications', 'launchAtLogin', 'ping', 'tunnelMode'\]\)/);
});

test('the Linux app owns its renderer and does not depend on the shared GUI assets', () => {
  const html = read('src/renderer/index.html');
  assert.match(html, /<script src="model\.js"><\/script>/);
  assert.match(html, /<script src="app\.js"><\/script>/);
  assert.doesNotMatch(html, /gui_assets|\.\.\/\.\.\//);
  assert.doesNotMatch(read('src/renderer/app.js'), /gui_assets/);
});
