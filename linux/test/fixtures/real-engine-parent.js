'use strict';

/* A stand-in for the Electron main process, used by real-engine-backend.test.mjs.
 *
 * It creates the real engine client against the real engine, prints one JSON
 * line, and then waits. The test kills this process with SIGKILL, which is what
 * an Electron crash looks like to the engine, and checks that the engine exits
 * by itself. Nothing here needs root, creates a TUN device, or changes a route.
 *
 * Environment: HOTSPOTSHADE_BIN (engine), HS_PARENT_HOME (temporary HOME),
 * HS_PARENT_MODE ("direct" or "standin"), HS_STANDIN_PID_FILE, HS_PARENT_PKEXEC and
 * HS_PARENT_HELPER (executable placeholder files for standin mode; never run).
 */

const path = require('node:path');
const { spawn } = require('node:child_process');
const { createEngineClient } = require('../../src/backend/engine-client.js');

const engine = process.env.HOTSPOTSHADE_BIN;
const home = process.env.HS_PARENT_HOME;
const mode = process.env.HS_PARENT_MODE || 'direct';
const standin = path.join(__dirname, 'real-engine-helper-standin.js');

function withHome(options) {
  return Object.assign({}, options, {
    env: Object.assign({}, options.env, {
      HOME: home,
      HS_STANDIN_ENGINE: engine,
      HS_STANDIN_HOME: home,
      HS_STANDIN_PID_FILE: process.env.HS_STANDIN_PID_FILE || ''
    })
  });
}

const client = mode === 'standin'
  ? createEngineClient({
    privileged: true,
    pkexecPath: process.env.HS_PARENT_PKEXEC,
    helperPath: process.env.HS_PARENT_HELPER,
    enginePath: engine,
    spawn: (command, args, options) => spawn(process.execPath, [standin], withHome(options))
  })
  : createEngineClient({
    executable: engine,
    spawn: (command, args, options) => spawn(command, args, withHome(options))
  });

client.call('status').then(() => {
  process.stdout.write(JSON.stringify({ pid: client.pid, tempDirectory: client.tempDirectory }) + '\n');
  setInterval(() => {}, 1000);
}, (error) => {
  process.stderr.write(String(error && error.message) + '\n');
  process.exit(1);
});
