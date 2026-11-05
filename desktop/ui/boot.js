/* Apply the stored appearance before the stylesheet loads.
 *
 * A stored value of "system" follows the operating system. "light" and "dark"
 * are explicit choices. The page stores only the preference. The effective
 * theme goes on the html element.
 */
(function () {
  'use strict';

  var KEY = 'hs-theme';
  var preference = 'system';
  try {
    var stored = localStorage.getItem(KEY);
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      preference = stored;
    }
  } catch (error) {
    preference = 'system';
  }

  var dark = false;
  if (preference === 'dark') {
    dark = true;
  } else if (preference === 'system') {
    try {
      dark = !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    } catch (error) {
      dark = false;
    }
  }

  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme-preference', preference);
})();
