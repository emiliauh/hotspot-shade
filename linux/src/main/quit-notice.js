'use strict';

/* Adapter from the lifecycle's fixed notice to the native warning dialog. */
function createQuitNoticeReporter(dialog, logError) {
  const log = typeof logError === 'function' ? logError : function () {};
  return function (notice) {
    const title = notice && typeof notice.title === 'string' ? notice.title : 'HotspotShade';
    const message = notice && typeof notice.message === 'string' && notice.message
      ? notice.message
      : 'The engine did not stop cleanly.';
    const detail = notice && typeof notice.detail === 'string' && notice.detail
      ? notice.detail
      : 'Check the engine and the routes before you start HotspotShade again.';
    log(message);
    try {
      dialog.showMessageBoxSync({
        type: 'warning',
        buttons: ['OK'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
        title: title,
        message: message,
        detail: detail
      });
    } catch (error) {
      log('The quit message could not be shown.');
    }
  };
}

module.exports = { createQuitNoticeReporter: createQuitNoticeReporter };
