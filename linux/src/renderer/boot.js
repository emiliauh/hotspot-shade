/* Set the saved or system appearance before the stylesheet loads. Local only. */
(function () {
  'use strict';
  var preference = 'system';
  try {
    var saved = localStorage.getItem('hs-linux-theme');
    if (saved === 'system' || saved === 'light' || saved === 'dark') preference = saved;
  } catch (error) {
    preference = 'system';
  }
  var dark = false;
  try {
    dark = !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  } catch (error) {
    dark = false;
  }
  var theme = preference === 'dark' || preference === 'light' ? preference : (dark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', theme);
  document.documentElement.setAttribute('data-theme-preference', preference);
  var highContrast = false;
  try {
    highContrast = !!(window.matchMedia
      && (window.matchMedia('(prefers-contrast: more)').matches
        || window.matchMedia('(forced-colors: active)').matches));
  } catch (error) {
    highContrast = false;
  }
  document.documentElement.setAttribute('data-contrast', highContrast ? 'high' : 'normal');
})();
