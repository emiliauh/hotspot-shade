'use strict';

/* Desktop notifications for the Linux target app.
 *
 * The policy is pure. It notifies for an automatic stop and for a pairing
 * result. A user stop never sends a message. A state that existed before the
 * app started is not a new event. Each message kind is limited to one message
 * in a 60 second window.
 *
 * The app setting and the desktop support are checked on every evaluation, so
 * a change applies at once. The messages hold no address, host, token, or key.
 */

const TITLE = 'HotspotShade';
const DEBOUNCE_MS = 60000;
const MAX_BODY = 240;

const AUTO_STOP_REASONS = Object.freeze({
  hotspot_lost: 'The hotspot turned off, so HotspotShade turned the tunnel off.',
  source_device_gone: 'The source device stopped answering, so HotspotShade turned the tunnel off.'
});

const PAIRING_SUCCESS = 'Paired with your source device.';
const PAIRING_FAILURE = 'The pairing did not finish. Check the code on your source device.';
const TUNNEL_ERROR = 'The tunnel stopped because of an error.';

function sanitize(value, limit) {
  if (typeof value !== 'string') return '';
  const message = value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/[ \t\r\n]+/g, ' ')
    .trim();
  const maximum = Number.isInteger(limit) ? limit : MAX_BODY;
  return message.slice(0, maximum);
}

function stopKey(status) {
  const data = status && typeof status === 'object' ? status : {};
  const stop = data.last_stop && typeof data.last_stop === 'object' ? data.last_stop : {};
  return [
    sanitize(String(stop.reason || '')),
    sanitize(String(stop.at === undefined || stop.at === null ? '' : stop.at)),
    sanitize(data.last_stop_message)
  ].join('|');
}

function stopReason(status) {
  const data = status && typeof status === 'object' ? status : {};
  const stop = data.last_stop && typeof data.last_stop === 'object' ? data.last_stop : {};
  return sanitize(String(stop.reason || ''));
}

function pairingState(pair) {
  const data = pair && typeof pair === 'object' ? pair : {};
  return sanitize(String(data.state || ''));
}

function isActivePairing(state) {
  return state === 'connecting' || state === 'confirm' || state === 'starting';
}

function createNotificationPolicy(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const now = typeof settings.now === 'function' ? settings.now : Date.now;
  const debounceMs = Number.isInteger(settings.debounceMs) && settings.debounceMs >= 0
    ? settings.debounceMs
    : DEBOUNCE_MS;

  const lastFired = new Map();
  let primed = false;
  let seenStop = '';
  let seenPairing = '';

  function canFire(kind) {
    const last = lastFired.get(kind);
    if (last === undefined) return true;
    return now() - last >= debounceMs;
  }

  function fire(kind, body, messages) {
    lastFired.set(kind, now());
    messages.push({ kind: kind, title: TITLE, body: body });
  }

  /* One evaluation. It returns the messages to post now. */
  function evaluate(input) {
    const data = input && typeof input === 'object' ? input : {};
    const enabled = data.enabled === true && data.supported === true;
    const focused = data.isFocused === true;
    const status = data.status && typeof data.status === 'object' ? data.status : null;
    const pair = data.pair && typeof data.pair === 'object' ? data.pair : null;
    const currentStop = status ? stopKey(status) : '';
    const currentPairing = pair ? pairingState(pair) : '';
    const messages = [];

    if (!primed) {
      primed = true;
      seenStop = currentStop;
      seenPairing = currentPairing;
      return { messages: messages };
    }

    if (status && currentStop !== seenStop) {
      seenStop = currentStop;
      const reason = stopReason(status);
      const engineMessage = sanitize(status.last_stop_message);
      if (enabled && reason !== '' && reason !== 'user') {
        if (AUTO_STOP_REASONS[reason]) {
          /* An automatic stop is important even when the window is focused. */
          if (canFire('auto-stop')) {
            fire('auto-stop', engineMessage || AUTO_STOP_REASONS[reason], messages);
          }
        } else if (reason === 'error' && !focused) {
          if (canFire('tunnel-error')) {
            fire('tunnel-error', engineMessage || TUNNEL_ERROR, messages);
          }
        }
      }
    }

    if (pair && currentPairing !== seenPairing) {
      const previous = seenPairing;
      seenPairing = currentPairing;
      if (enabled && isActivePairing(previous)) {
        if (currentPairing === 'paired') {
          if (canFire('pairing')) fire('pairing', PAIRING_SUCCESS, messages);
        } else if (currentPairing === 'failed') {
          const error = sanitize(pair.error);
          if (canFire('pairing')) fire('pairing', error || PAIRING_FAILURE, messages);
        }
      }
    } else if (!pair) {
      seenPairing = currentPairing;
    }

    return { messages: messages };
  }

  return Object.freeze({
    evaluate: evaluate,
    state: function () {
      return {
        primed: primed,
        seenStop: seenStop,
        seenPairing: seenPairing
      };
    }
  });
}

/* The system sink. One delivered message per kind is kept. A newer message
 * replaces the older one. `clearDelivered` closes every message. */
function createElectronNotificationSink(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const Notification = settings.Notification;
  const iconPath = typeof settings.iconPath === 'string' ? settings.iconPath : '';
  const onClick = typeof settings.onClick === 'function' ? settings.onClick : null;
  const live = new Map();

  const supported = !!(Notification
    && typeof Notification === 'function'
    && typeof Notification.isSupported === 'function'
    && Notification.isSupported());

  function close(kind) {
    const previous = live.get(kind);
    if (!previous) return;
    live.delete(kind);
    try {
      previous.close();
    } catch (error) {
      /* The desktop may have closed the message first. */
    }
  }

  function post(message) {
    if (!supported || !message || typeof message.body !== 'string') return false;
    close(message.kind);
    let notification;
    try {
      notification = new Notification({
        title: typeof message.title === 'string' && message.title ? message.title : TITLE,
        body: message.body,
        icon: iconPath || undefined,
        silent: false
      });
    } catch (error) {
      return false;
    }
    if (onClick && typeof notification.on === 'function') {
      notification.on('click', onClick);
    }
    try {
      notification.show();
    } catch (error) {
      return false;
    }
    live.set(message.kind, notification);
    return true;
  }

  function clearDelivered() {
    for (const kind of Array.from(live.keys())) close(kind);
  }

  return Object.freeze({
    supported: supported,
    clearDelivered: clearDelivered,
    post: post
  });
}

module.exports = {
  AUTO_STOP_REASONS: AUTO_STOP_REASONS,
  DEBOUNCE_MS: DEBOUNCE_MS,
  PAIRING_FAILURE: PAIRING_FAILURE,
  PAIRING_SUCCESS: PAIRING_SUCCESS,
  TITLE: TITLE,
  TUNNEL_ERROR: TUNNEL_ERROR,
  createElectronNotificationSink: createElectronNotificationSink,
  createNotificationPolicy: createNotificationPolicy,
  sanitize: sanitize,
  stopKey: stopKey
};
