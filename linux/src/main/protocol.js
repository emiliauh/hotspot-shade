'use strict';

/* Bounded input checks for the fixed IPC allowlist.
 *
 * A renderer compromise must not turn one call into a large allocation, a path
 * read, a URL request, or a command. Every payload is a plain object with exact
 * keys and bounded scalar values. Unknown keys are rejected.
 */

const SCENARIOS = require('../backend/demo-backend').SCENARIOS;
const { SETTING_NAMES, TUNNEL_MODES } = require('./settings');

const MAX_COPY_TEXT = 20000;
const MAX_ACTIVITY_SINCE = 1000000000;
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
const START_MODES = TUNNEL_MODES;

class ProtocolError extends Error {
  constructor(message) {
    super(message || 'The request is not valid.');
    this.name = 'ProtocolError';
    this.code = 'invalid_input';
  }
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  if (!isPlainObject(value)) throw new ProtocolError();
  const own = Object.keys(value);
  if (own.length !== keys.length) throw new ProtocolError();
  for (const key of own) {
    if (!keys.includes(key)) throw new ProtocolError();
  }
}

function noArgs(payload) {
  if (payload === undefined || payload === null) return undefined;
  throw new ProtocolError();
}

function startOptions(payload) {
  exactKeys(payload, ['mode', 'ping']);
  if (!START_MODES.includes(payload.mode)) throw new ProtocolError();
  if (typeof payload.ping !== 'boolean') throw new ProtocolError();
  /* Direct mode never uses the echo relay that ping controls. Normalize it
   * away so a direct start body stays fixed. */
  return { mode: payload.mode, ping: payload.mode === 'phone' ? payload.ping : false };
}

function activityQuery(payload) {
  exactKeys(payload, ['since']);
  if (!Number.isInteger(payload.since)) throw new ProtocolError();
  if (payload.since < 0 || payload.since > MAX_ACTIVITY_SINCE) throw new ProtocolError();
  return { since: payload.since };
}

function scenarioChoice(payload) {
  exactKeys(payload, ['name']);
  if (typeof payload.name !== 'string' || !SCENARIOS.includes(payload.name)) throw new ProtocolError();
  return { name: payload.name };
}

function copyText(payload) {
  exactKeys(payload, ['text']);
  if (typeof payload.text !== 'string') throw new ProtocolError();
  if (payload.text.length < 1 || payload.text.length > MAX_COPY_TEXT) throw new ProtocolError();
  if (CONTROL_CHARACTERS.test(payload.text)) throw new ProtocolError();
  return { text: payload.text };
}

function settingUpdate(payload) {
  exactKeys(payload, ['name', 'value']);
  if (typeof payload.name !== 'string' || !SETTING_NAMES.includes(payload.name)) throw new ProtocolError();
  if (payload.name === 'tunnelMode') {
    if (!TUNNEL_MODES.includes(payload.value)) throw new ProtocolError();
    return { name: payload.name, value: payload.value };
  }
  if (typeof payload.value !== 'boolean') throw new ProtocolError();
  return { name: payload.name, value: payload.value };
}

module.exports = {
  MAX_ACTIVITY_SINCE: MAX_ACTIVITY_SINCE,
  MAX_COPY_TEXT: MAX_COPY_TEXT,
  ProtocolError: ProtocolError,
  START_MODES: START_MODES,
  TUNNEL_MODES: TUNNEL_MODES,
  activityQuery: activityQuery,
  copyText: copyText,
  isPlainObject: isPlainObject,
  noArgs: noArgs,
  scenarioChoice: scenarioChoice,
  settingUpdate: settingUpdate,
  startOptions: startOptions
};
