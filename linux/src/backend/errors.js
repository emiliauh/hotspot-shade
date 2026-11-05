'use strict';

/* One plain error shape for the Linux backend.
 *
 * The code is a short fixed word. The message is plain text for a person. No
 * error holds a token, a secret, an identity key, or a command line.
 */

class BackendError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'BackendError';
    this.code = typeof code === 'string' && code ? code : 'backend_error';
    this.status = Number.isInteger(status) ? status : 400;
  }
}

function isBackendError(value) {
  return value instanceof BackendError;
}

module.exports = {
  BackendError: BackendError,
  isBackendError: isBackendError
};
