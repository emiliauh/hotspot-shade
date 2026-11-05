'use strict';

/* The one native window. The frame, title bar, window controls, and menu bar
 * are native to the Linux desktop. The page cannot open a second window.
 */

const path = require('node:path');
const { SAFE_WEB_PREFERENCES } = require('./security');

function createMainWindow(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const BrowserWindow = settings.BrowserWindow;
  const appRoot = settings.appRoot;
  const preloadPath = settings.preloadPath;
  const iconPath = settings.iconPath;

  if (!BrowserWindow) throw new TypeError('BrowserWindow is required.');
  if (typeof appRoot !== 'string' || !appRoot) throw new TypeError('The app root is required.');
  if (typeof preloadPath !== 'string' || !preloadPath) throw new TypeError('The preload path is required.');

  const window = new BrowserWindow({
    width: 1000,
    height: 720,
    minWidth: 780,
    minHeight: 560,
    useContentSize: true,
    show: false,
    center: true,
    title: 'HotspotShade',
    frame: true,
    titleBarStyle: 'default',
    autoHideMenuBar: false,
    icon: iconPath,
    backgroundColor: '#f6f6f8',
    webPreferences: Object.assign({}, SAFE_WEB_PREFERENCES, {
      preload: preloadPath
    })
  });

  window.setMenuBarVisibility(true);
  window.once('ready-to-show', function () {
    window.show();
  });

  const indexPath = path.join(appRoot, 'index.html');
  window.loadFile(indexPath);
  return window;
}

module.exports = {
  createMainWindow: createMainWindow
};
