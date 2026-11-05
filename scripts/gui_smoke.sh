#!/usr/bin/env bash
# Smoke-test the local GUI in demo mode. It needs no root, no routes, and no
# phone. Usage: scripts/gui_smoke.sh PATH_TO_HOTSPOTSHADE_BINARY [PORT]
set -euo pipefail
BIN="${1:?usage: gui_smoke.sh BINARY [PORT]}"
PORT="${2:-8794}"
BASE="http://127.0.0.1:${PORT}"
LOG="$(mktemp)"
"$BIN" gui --demo --no-open --port "$PORT" >"$LOG" 2>&1 &
PID=$!
cleanup() { kill -TERM "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -f "$LOG" "$LOG.h"; }
trap cleanup EXIT

for _ in $(seq 1 50); do
  curl -fsS --max-time 1 "$BASE/api/status" >/dev/null 2>&1 && break
  sleep 0.2
done

fail() { echo "FAIL: $1"; echo "--- GUI log"; cat "$LOG"; exit 1; }

curl -fsS "$BASE/" -o /dev/null -D - | tr -d '\r' >"$LOG.h" || fail "GET / failed"
grep -qi '^content-security-policy:' "$LOG.h" || fail "no Content-Security-Policy header"
curl -fsS "$BASE/favicon.svg" -o /dev/null -D - | tr -d '\r' >"$LOG.h" || fail "GET /favicon.svg failed"
grep -qi '^content-type: image/svg+xml' "$LOG.h" || fail "favicon has the wrong content type"
STATUS="$(curl -fsS "$BASE/api/status")" || fail "GET /api/status failed"
echo "$STATUS" | grep -q '"demo":true' || fail "status does not report demo mode"
echo "$STATUS" | grep -q '"running":false' || fail "demo backend should start stopped"

# No external asset may load: the page and its assets use only local paths.
for path in / /styles.css /app.js /favicon.svg; do
  if curl -fsS "$BASE$path" | grep -Eqi '(src|href)=["'"'"']https?://|url\(https?://|@import +["'"'"']?https?://'; then
    fail "external asset reference in $path"
  fi
done

# A request with a foreign Host header must be refused.
CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: attacker.invalid' "$BASE/api/status")"
[ "$CODE" = "403" ] || fail "foreign Host header returned $CODE, expected 403"

# Pairing routes. The demo backend simulates the pairing and makes no connection.
PAIR="$(curl -fsS "$BASE/api/phone/pair")" || fail "GET /api/phone/pair failed"
echo "$PAIR" | grep -q '"state":"idle"' || fail "pairing should start idle"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/phone/pair")"
[ "$CODE" = "415" ] || fail "pairing POST without JSON returned $CODE, expected 415"
PAIR="$(curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/phone/pair")" || fail "POST /api/phone/pair failed"
echo "$PAIR" | grep -q '"state":"connecting"' || fail "pairing should report connecting"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/phone/pair")"
[ "$CODE" = "400" ] || fail "a second pairing start returned $CODE, expected 400"
PAIR="$(curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/phone/pair/cancel")" || fail "cancel failed"
echo "$PAIR" | grep -q '"state":"idle"' || fail "cancel should return to idle"
curl -fsS "$BASE/api/status" | grep -q '"paired":false' || fail "status does not report the pairing"
curl -fsS "$BASE/api/status" | grep -qi 'token' && fail "status mentions a token"

echo "GUI smoke test passed"
