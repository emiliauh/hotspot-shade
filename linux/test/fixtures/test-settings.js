'use strict';

/* A settings store for the hermetic Electron harnesses.
 *
 * It writes under the temporary user-data directory. It never touches the
 * person's XDG autostart directory.
 */

const path = require('node:path');
const { createAutostart } = require('../../src/main/autostart');
const { createSettingsStore } = require('../../src/main/settings');

function createTestSettingsStore(userData, notificationsSupported = false) {
  return createSettingsStore({
    filePath: path.join(userData, 'settings.json'),
    autostart: createAutostart({
      env: { HS_AUTOSTART_DIR: path.join(userData, 'autostart') },
      execPath: process.execPath
    }),
    notificationsSupported: notificationsSupported
  });
}

module.exports = {
  createTestSettingsStore: createTestSettingsStore
};
