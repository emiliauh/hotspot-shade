// Focused tests for destination privacy reporting in app.js. The page has no
// build step and no module export. The test reads the real source and runs the
// pure reporting helpers in an isolated context.
//
// The contract under test: the page echoes a destination-privacy token from the
// backend or says that no token was reported. It never invents a mode, never
// turns a missing, malformed, or unsupported capability into an active hiding
// claim, and never copies a name, address, or secret into the diagnostics text.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('./app.js', import.meta.url), 'utf8');

function slice(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  assert.ok(start > 0, 'missing source marker: ' + startMarker);
  assert.ok(end > start, 'missing end marker: ' + endMarker + ' after ' + startMarker);
  return source.slice(start, end);
}

// The helpers reference `state`, `num`, `pickNumber`, and `plainInt`. Take the
// real functions so the test cannot drift from the page.
const script = [
  'var state = { status: null, probe: null };',
  slice('function num(value) {', 'function pickNumber(obj) {'),
  slice('function pickNumber(obj) {', 'function formatInt(value) {'),
  slice('function platformInfo() {', 'function displayOs(value) {'),
  slice('var PRIVACY_MODES', 'function resolveMode(mode) {'),
  slice('function plainInt(value) {', 'function copyDiagnosticsReport() {'),
  'globalThis.__privacyApi = {' +
  ' state: state,' +
  ' destinationPrivacy: destinationPrivacy,' +
  ' destinationPrivacyRow: destinationPrivacyRow,' +
  ' privacyState: privacyState,' +
  ' diagnosticsReport: diagnosticsReport,' +
  ' PRIVACY_MODES: PRIVACY_MODES,' +
  ' PRIVACY_STATES: PRIVACY_STATES' +
  ' };'
].join('\n');

const context = {};
vm.runInNewContext(script, context);
const api = context.__privacyApi;

function setPlatform(payload) {
  api.state.status = { platform: payload };
  api.state.probe = {};
}

function rowFor(privacy) {
  return api.destinationPrivacyRow(privacy);
}

const MODE_BADGES = ['Off', 'Shape', 'Hide', 'Cover', 'Unknown', 'Unsupported', 'Not supported', 'Not reported'];
// Words that would turn an echo of the backend mode into a claim that hiding
// runs now. "reported" and "supported" are not claims of an active mode.
const ACTIVE_WORDS = /\b(active|enabled|hiding|hides|hidden|protected|concealed)\b/i;

function capabilityToken(detail, label) {
  const pattern = new RegExp(label + ' (supported|unsupported|unavailable|unverified|not reported)');
  const match = pattern.exec(detail);
  return match ? match[1] : null;
}

function assertNoActiveHidingClaim(row, label) {
  assert.ok(row, label + ': expected a row or null, got ' + JSON.stringify(row));
  assert.equal(row.name, 'Destination privacy', label);
  assert.ok(MODE_BADGES.indexOf(row.badge) >= 0, label + ': unexpected badge ' + row.badge);
  assert.ok(!ACTIVE_WORDS.test(row.detail), label + ': detail claims an active mode: ' + row.detail);
  if (row.state === 'ok') {
    assert.ok(!/^(hide|cover)$/i.test(row.badge), label + ': a healthy row must not badge ' + row.badge);
  }
  assert.ok(typeof row.detail === 'string' && row.detail.length > 0, label + ': empty detail');
}

test('the current build payload reports off and never claims hiding', () => {
  setPlatform({
    destination_privacy: {
      mode: 'off',
      default_mode: 'off',
      modes: { off: 'supported', shape: 'unsupported', hide: 'unsupported', cover: 'unsupported' },
      sni_override: 'unsupported',
      ech: 'unsupported',
      background_relay: 'unverified'
    }
  });
  const privacy = api.destinationPrivacy();
  assert.ok(privacy && privacy.mode === 'off', 'the platform row must be found');
  const row = rowFor(privacy);
  assertNoActiveHidingClaim(row, 'off');
  assert.equal(row.badge, 'Off');
  assert.match(row.detail, /does not add destination-name privacy/);
  assert.equal(capabilityToken(row.detail, 'SNI override'), 'unsupported');
  assert.equal(capabilityToken(row.detail, 'ECH'), 'unsupported');
});

test('a supported mechanism does not turn an off mode into a hiding claim', () => {
  const row = rowFor({ mode: 'off', sni_override: 'supported', ech: 'supported' });
  assertNoActiveHidingClaim(row, 'off with supported mechanisms');
  assert.equal(row.badge, 'Off');
  assert.match(row.detail, /does not add destination-name privacy/);
});

test('missing capability data reports no row', () => {
  const cases = [
    ['no platform object', undefined],
    ['empty platform', {}],
    ['undefined row', { destination_privacy: undefined }],
    ['null row', { destination_privacy: null }],
    ['string row', { destination_privacy: 'hide' }],
    ['number row', { destination_privacy: 7 }],
    ['boolean row', { destination_privacy: true }],
    ['empty array', { destination_privacy: [] }],
    ['array of modes', { destination_privacy: ['hide'] }]
  ];
  for (const [label, payload] of cases) {
    setPlatform(payload);
    assert.equal(api.destinationPrivacy(), null, label + ': no row may be invented');
    assert.equal(rowFor(api.destinationPrivacy()), null, label + ': no health row may be invented');
  }
});

test('a row from only the probe is still never an active hiding claim', () => {
  api.state.status = {};
  api.state.probe = { platform: { destination_privacy: { mode: 'hide', ech: 'supported' } } };
  const row = rowFor(api.destinationPrivacy());
  if (row) assertNoActiveHidingClaim(row, 'probe-only row');
});

test('a malformed mode becomes an unknown row, not a hiding claim', () => {
  const values = ['', '   ', 'HIDDEN', 'hide mode', 'hide\n', ' hide ', 7, {}, [], true, null, undefined, 'offf'];
  for (const value of values) {
    const row = rowFor({ mode: value });
    const label = 'mode ' + JSON.stringify(value);
    assert.ok(row, label + ': an unknown mode still gets a row');
    assert.equal(row.state, 'fail', label);
    assert.equal(row.badge, 'Unknown', label);
    assert.match(row.detail, /no mode from the schema/i, label);
    assertNoActiveHidingClaim(row, label);
  }
});

test('capability tokens are echoed and never upgraded', () => {
  const cases = [
    ['supported', 'supported'],
    ['SUPPORTED', 'supported'],
    ['unsupported', 'unsupported'],
    ['UNSUPPORTED', 'unsupported'],
    ['unavailable', 'unavailable'],
    ['unverified', 'unverified'],
    ['yes', 'not reported'],
    ['supported ', 'not reported'],
    ['', 'not reported'],
    [7, 'not reported'],
    [[], 'not reported'],
    [{}, 'not reported'],
    [null, 'not reported']
  ];
  for (const [value, expected] of cases) {
    const row = rowFor({ mode: 'off', sni_override: value, ech: value });
    const label = 'token ' + JSON.stringify(value);
    assert.equal(capabilityToken(row.detail, 'SNI override'), expected, label);
    assert.equal(capabilityToken(row.detail, 'ECH'), expected, label);
    assertNoActiveHidingClaim(row, label);
  }
});

test('contradictory capability data keeps the tokens visible and makes no active claim', () => {
  // The build marks hide unsupported but a status row reports mode hide.
  const row = rowFor({
    mode: 'hide',
    modes: { off: 'supported', shape: 'unsupported', hide: 'unsupported', cover: 'unsupported' },
    sni_override: 'unsupported',
    ech: 'unsupported'
  });
  assertNoActiveHidingClaim(row, 'hide with unsupported capability');
  assert.notEqual(row.state, 'ok', 'a contradictory row must not read as healthy');
  assert.match(row.detail, /report/i, 'the row must attribute the mode to the backend');
  assert.equal(capabilityToken(row.detail, 'SNI override'), 'unsupported');
  assert.equal(capabilityToken(row.detail, 'ECH'), 'unsupported');

  // The mode is off while the capability map says hide and cover are supported.
  const supportedRow = rowFor({
    mode: 'off',
    modes: { off: 'supported', shape: 'supported', hide: 'supported', cover: 'supported' },
    sni_override: 'supported',
    ech: 'supported'
  });
  assertNoActiveHidingClaim(supportedRow, 'off with supported modes');
  assert.equal(supportedRow.badge, 'Off');
  assert.match(supportedRow.detail, /does not add destination-name privacy/);

  // A cover mode that the same payload marks unsupported stays a note.
  const coverRow = rowFor({ mode: 'cover', modes: { cover: 'unsupported' }, ech: 'unsupported' });
  assertNoActiveHidingClaim(coverRow, 'cover with unsupported capability');
  assert.notEqual(coverRow.state, 'ok');
});

// Known gap, recorded so it stays visible without breaking the build. The row
// A contradictory mode must not receive a mode badge.
test('a mode that the payload marks unsupported must not get a hiding badge', () => {
  const row = rowFor({ mode: 'hide', modes: { hide: 'unsupported' } });
  assert.notEqual(row.badge, 'Hide');
  assert.equal(row.state, 'fail');
});

test('the diagnostics copy stays on counters and mode tokens', () => {
  const data = {
    running: true,
    token: 'tok-secret',
    host: 'secret.example',
    address: '203.0.113.5',
    engine: { version: '0.1.0', uptime_s: 12, workers: 2, name: 'secret.example' },
    setup: { connect_ms: { count: 1, p50: 2, p95: 3, max: 4 } },
    dns: { lookups: 3, ok: 2, failed: 1, ms: { count: 3, p50: 1, p95: 2, max: 3 }, name: 'secret.example' },
    queues: { input: [{ peak: 1, max_age_us: 2 }], output: { peak: 1, max_age_us: 2 } },
    udp: { flows: 1, age_drops: 0 },
    tcp: { flows_peak: 1, retransmits: 0, zero_window_ms: 0 },
    destination_privacy: {
      mode: 'off',
      sni_override: 'unsupported',
      ech: 'unsupported',
      modes: { off: 'supported', shape: 'unsupported', hide: 'unsupported', cover: 'unsupported' },
      counters: {
        shaped_flows: 0, ech_attempts: 0, ech_ok: 0, ech_rejected: 0,
        ech_fallback: 0, doh_lookups: 0, doh_failed: 0
      },
      name: 'secret.example',
      host: 'secret.example',
      sni: 'secret.example',
      address: '203.0.113.5',
      ech_config: 'AEX-secret',
      certificate: 'BEGIN CERTIFICATE',
      token: 'tok-secret'
    },
    failures: { total: 0, dropped: 0, note: 'secret.example' }
  };
  const text = api.diagnosticsReport(data);
  assert.match(text, /^Destination privacy: mode off\./m, 'the mode line must stay present');
  assert.match(text, /Shaped flows 0/, 'counters must stay present');
  for (const leak of ['secret', '203.0.113.5', 'AEX', 'BEGIN', 'tok-', 'secret.example']) {
    assert.ok(!text.includes(leak), 'diagnostics leaked ' + leak + ':\n' + text);
  }
  assert.ok(!/\b\d{1,3}(\.\d{1,3}){3}\b/.test(text), 'diagnostics printed an IPv4 address');
});

test('diagnostics reports the target TCP gauge only when supplied', () => {
  assert.match(api.diagnosticsReport({ tcp: { flows_active: 3 } }), /Target TCP flows active: 3/);
  assert.match(api.diagnosticsReport({ tcp: {} }), /Target TCP flows active: not reported/);
  assert.match(api.diagnosticsReport({ tcp: { flows_active: 'invalid' } }), /Target TCP flows active: not reported/);
});

test('a malformed diagnostics mode reads as not reported', () => {
  const cases = [
    ['no section', {}],
    ['null section', { destination_privacy: null }],
    ['string section', { destination_privacy: 'hide' }],
    ['array section', { destination_privacy: [] }],
    ['array mode', { destination_privacy: { mode: ['hide'] } }],
    ['object mode', { destination_privacy: { mode: { value: 'hide' } } }],
    ['injected mode', { destination_privacy: { mode: 'hide token=tok-secret' } }],
    ['unknown mode', { destination_privacy: { mode: 'hidden' } }]
  ];
  for (const [label, data] of cases) {
    const text = api.diagnosticsReport(data);
    assert.match(text, /Destination privacy: mode not reported\./, label + ':\n' + text);
    assert.ok(!text.includes('tok-secret'), label + ': diagnostics leaked a token');
    assert.ok(!/mode hide\b/.test(text), label + ': diagnostics claimed a hide mode');
  }
});

test('a valid diagnostics mode is echoed and never dressed as active', () => {
  for (const mode of ['off', 'shape', 'hide', 'cover']) {
    const text = api.diagnosticsReport({ destination_privacy: { mode: mode, counters: {} } });
    assert.ok(text.includes('Destination privacy: mode ' + mode + '.'), mode + ' must be echoed:\n' + text);
    const privacyLine = text.split('\n').find(line => line.startsWith('Destination privacy:'));
    assert.ok(!ACTIVE_WORDS.test(privacyLine), mode + ': diagnostics claimed an active mode');
  }
});

test('malformed counters print numbers and keep their text out of the report', () => {
  const data = {
    destination_privacy: {
      mode: 'off',
      counters: {
        ech_ok: { value: 5, name: 'secret.example' },
        doh_lookups: '7 (secret.example)',
        ech_attempts: ['9', 'secret.example'],
        shaped_flows: null
      }
    }
  };
  const text = api.diagnosticsReport(data);
  assert.match(text, /ECH attempts 9/, 'a numeric prefix must be read as a number');
  assert.match(text, /ok 0/, 'an object counter must read as zero');
  assert.match(text, /DoH lookups 7/, 'a numeric prefix must be read as a number');
  assert.match(text, /Shaped flows 0/, 'a null counter must read as zero');
  assert.ok(!text.includes('secret'), 'diagnostics leaked counter text:\n' + text);
  assert.ok(!text.includes('[object Object]'), 'diagnostics printed a raw object');
  assert.ok(!text.includes('9,'), 'diagnostics printed raw array text');
});
