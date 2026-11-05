'use strict';

/* The native application menu.
 *
 * Every item runs one fixed action. A menu item cannot name a URL, a command,
 * a file, or a page string. Page actions go through the fixed menu command
 * channel. Window actions use the native Electron window API.
 */

const { MENU_COMMANDS, MENU_COMMAND_CHANNEL } = require('./channels');

function createTemplate(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const app = settings.app;
  const window = settings.window;
  const sendCommand = settings.sendCommand;
  const showAbout = settings.showAbout;
  const onSettings = typeof settings.onSettings === 'function' ? settings.onSettings : null;
  const engineMode = settings.engineMode === true;

  function send(command) {
    if (MENU_COMMANDS.includes(command) && typeof sendCommand === 'function') {
      sendCommand(command);
    }
  }

  function toggleMaximized() {
    if (!window) return;
    if (window.isMaximized()) window.unmaximize();
    else window.maximize();
  }

  const helpItems = [
    {
      label: 'Limitations',
      click: function () { send('demo-limitations'); }
    }
  ];
  if (!engineMode) {
    helpItems.push({
      label: 'Demo Scenarios',
      click: function () { send('demo-scenarios'); }
    });
  }
  helpItems.push({ type: 'separator' });
  helpItems.push({
    label: 'About HotspotShade',
    click: function () {
      if (typeof showAbout === 'function') showAbout();
    }
  });

  return [
    {
      label: 'File',
      submenu: [
        {
          label: 'Settings...',
          accelerator: 'CmdOrCtrl+,',
          click: function () {
            if (onSettings) onSettings();
            else send('settings');
          }
        },
        { type: 'separator' },
        {
          label: 'Quit HotspotShade',
          accelerator: 'CmdOrCtrl+Q',
          click: function () {
            if (app && typeof app.quit === 'function') app.quit();
          }
        }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        {
          label: 'Dashboard',
          accelerator: 'CmdOrCtrl+1',
          click: function () { send('dashboard'); }
        },
        {
          label: 'Activity',
          accelerator: 'CmdOrCtrl+2',
          click: function () { send('activity'); }
        },
        { type: 'separator' },
        {
          label: 'Refresh Status',
          accelerator: 'CmdOrCtrl+R',
          click: function () { send('refresh'); }
        },
        {
          label: 'Check Source Device Now',
          accelerator: 'CmdOrCtrl+Shift+K',
          click: function () { send('check-now'); }
        },
        { type: 'separator' },
        {
          label: 'Toggle Appearance',
          accelerator: 'CmdOrCtrl+Shift+L',
          click: function () { send('theme'); }
        }
      ]
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        {
          label: 'Maximize',
          click: toggleMaximized
        },
        { type: 'separator' },
        { role: 'close' }
      ]
    },
    {
      label: 'Help',
      submenu: helpItems
    }
  ];
}

function sendMenuCommand(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const window = settings.window;
  const command = settings.command;
  if (!MENU_COMMANDS.includes(command)) return false;
  if (!window || !window.webContents || typeof window.webContents.send !== 'function') return false;
  window.webContents.send(MENU_COMMAND_CHANNEL, command);
  return true;
}

function buildApplicationMenu(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const Menu = settings.Menu;
  if (!Menu || typeof Menu.buildFromTemplate !== 'function') throw new TypeError('The native Menu is required.');
  const template = createTemplate(settings);
  return Menu.buildFromTemplate(template);
}

module.exports = {
  buildApplicationMenu: buildApplicationMenu,
  createTemplate: createTemplate,
  sendMenuCommand: sendMenuCommand
};
