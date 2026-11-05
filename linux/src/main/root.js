'use strict';

/* The desktop app must run as the desktop user, never as root.
 *
 * The privileged helper is a separate process. The window, the renderer, and
 * the engine client stay unprivileged. An accidental `sudo hotspotshade`
 * launch stops with one plain message.
 */

const ROOT_REFUSAL = 'HotspotShade must not run as root. Start it as your desktop user.';

function isRootUid(uid) {
  return typeof uid === 'number' && Number.isInteger(uid) && uid === 0;
}

function shouldRefuse(uid) {
  return isRootUid(uid);
}

module.exports = {
  ROOT_REFUSAL: ROOT_REFUSAL,
  isRootUid: isRootUid,
  shouldRefuse: shouldRefuse
};
