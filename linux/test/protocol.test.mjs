import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const protocol = require('../src/main/protocol.js');
const channels = require('../src/main/channels.js');
const model = require('../src/renderer/model.js');

test('arguments that take no payload reject every value', () => {
  assert.equal(protocol.noArgs(undefined), undefined);
  assert.equal(protocol.noArgs(null), undefined);
  assert.throws(() => protocol.noArgs({}), protocol.ProtocolError);
  assert.throws(() => protocol.noArgs([]), protocol.ProtocolError);
  assert.throws(() => protocol.noArgs('status'), protocol.ProtocolError);
});

test('the start payload has one boolean and no extra keys', () => {
  assert.deepEqual(protocol.startOptions({ ping: true }), { ping: true });
  assert.deepEqual(protocol.startOptions({ ping: false }), { ping: false });
  assert.throws(() => protocol.startOptions({ ping: 'true' }), protocol.ProtocolError);
  assert.throws(() => protocol.startOptions({ ping: true, iface: 'wlan0' }), protocol.ProtocolError);
  assert.throws(() => protocol.startOptions({}), protocol.ProtocolError);
  assert.throws(() => protocol.startOptions(null), protocol.ProtocolError);
  assert.throws(() => protocol.startOptions([]), protocol.ProtocolError);
});

test('the activity sequence is a bounded integer', () => {
  assert.deepEqual(protocol.activityQuery({ since: 0 }), { since: 0 });
  assert.deepEqual(protocol.activityQuery({ since: 1000 }), { since: 1000 });
  assert.throws(() => protocol.activityQuery({ since: -1 }), protocol.ProtocolError);
  assert.throws(() => protocol.activityQuery({ since: 1.5 }), protocol.ProtocolError);
  assert.throws(() => protocol.activityQuery({ since: '1' }), protocol.ProtocolError);
  assert.throws(() => protocol.activityQuery({ since: 1000000001 }), protocol.ProtocolError);
  assert.throws(() => protocol.activityQuery({ since: 0, all: true }), protocol.ProtocolError);
});

test('the demo scenario is a fixed enum', () => {
  for (const name of ['ready', 'source-stopped', 'not-trusted', 'reset']) {
    assert.deepEqual(protocol.scenarioChoice({ name }), { name });
  }
  assert.throws(() => protocol.scenarioChoice({ name: 'tunnel-on' }), protocol.ProtocolError);
  assert.throws(() => protocol.scenarioChoice({ name: '' }), protocol.ProtocolError);
  assert.throws(() => protocol.scenarioChoice({ name: 'ready', force: true }), protocol.ProtocolError);
});

test('copied text is bounded and has no control characters', () => {
  assert.deepEqual(protocol.copyText({ text: 'a' }), { text: 'a' });
  assert.deepEqual(protocol.copyText({ text: 'line one\nline two\tok\r' }), { text: 'line one\nline two\tok\r' });
  const max = 'a'.repeat(protocol.MAX_COPY_TEXT);
  assert.equal(protocol.copyText({ text: max }).text.length, protocol.MAX_COPY_TEXT);
  assert.throws(() => protocol.copyText({ text: '' }), protocol.ProtocolError);
  assert.throws(() => protocol.copyText({ text: max + 'a' }), protocol.ProtocolError);
  assert.throws(() => protocol.copyText({ text: 'bad\u0000text' }), protocol.ProtocolError);
  assert.throws(() => protocol.copyText({ text: 'bad\u001btext' }), protocol.ProtocolError);
  assert.throws(() => protocol.copyText({ text: 'ok', path: '/etc/passwd' }), protocol.ProtocolError);
});

test('plain objects are required', () => {
  assert.equal(protocol.isPlainObject({}), true);
  assert.equal(protocol.isPlainObject(Object.create(null)), true);
  assert.equal(protocol.isPlainObject([]), false);
  assert.equal(protocol.isPlainObject(new Date()), false);
  assert.equal(protocol.isPlainObject(null), false);
});

test('the channel and menu lists stay in one shape', () => {
  const values = Object.values(channels.IPC_CHANNELS);
  assert.equal(values.length, new Set(values).size);
  for (const value of values) assert.match(value, /^hs:[a-z-]+$/);
  assert.equal(channels.MENU_COMMAND_CHANNEL, 'hs:menu-command');
  for (const command of channels.MENU_COMMANDS) {
    assert.equal(model.menuCommandAllowed(command), true, command);
  }
  assert.equal(channels.MENU_COMMANDS.length, new Set(channels.MENU_COMMANDS).size);
});
