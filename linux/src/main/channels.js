'use strict';

/* The fixed IPC allowlist. The page cannot name a channel, a path, a URL, or a
 * command. Add one route per capability. The preload file repeats the channel
 * names because a sandboxed preload cannot load a local module. The asset test
 * checks that both lists stay the same.
 */

const IPC_CHANNELS = Object.freeze({
  bootstrap: 'hs:bootstrap',
  status: 'hs:status',
  pairState: 'hs:pair-state',
  pair: 'hs:pair',
  pairCancel: 'hs:pair-cancel',
  forget: 'hs:forget',
  start: 'hs:start',
  stop: 'hs:stop',
  probe: 'hs:probe',
  activity: 'hs:activity',
  failures: 'hs:failures',
  diagnostics: 'hs:diagnostics',
  copyText: 'hs:copy-text',
  demoScenario: 'hs:demo-scenario',
  openSettings: 'hs:open-settings',
  settingsUpdate: 'hs:settings-update'
});

const MENU_COMMAND_CHANNEL = 'hs:menu-command';

const MENU_COMMANDS = Object.freeze([
  'dashboard',
  'activity',
  'settings',
  'settings-inline',
  'advanced',
  'refresh',
  'check-now',
  'theme',
  'demo-limitations',
  'demo-scenarios'
]);

module.exports = {
  IPC_CHANNELS: IPC_CHANNELS,
  MENU_COMMAND_CHANNEL: MENU_COMMAND_CHANNEL,
  MENU_COMMANDS: MENU_COMMANDS
};
