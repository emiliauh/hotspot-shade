#!/bin/sh
# Run the Linux demo tests on the current Linux host.
#
# Requires Node.js 22 or later and a display. For a headless host, use
# scripts/test-container.sh instead.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

if [ ! -x node_modules/.bin/electron ]; then
  echo "Run npm ci first." >&2
  exit 2
fi

node --test test/*.test.mjs
if [ -n "${DISPLAY:-}" ]; then
  ./node_modules/.bin/electron test/smoke-main.js
  ./node_modules/.bin/electron test/settings-window-main.js
  ./node_modules/.bin/electron test/a11y-main.js
else
  xvfb-run -a ./node_modules/.bin/electron test/smoke-main.js
  xvfb-run -a ./node_modules/.bin/electron test/settings-window-main.js
  xvfb-run -a ./node_modules/.bin/electron test/a11y-main.js
fi
