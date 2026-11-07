#!/usr/bin/env bash
set -euo pipefail
# The inventory is an execution contract, not a correctness proof.
executable=$1 inventory=$2 sums=$3
sha256sum -c "$sums"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$executable" --list | sed -n 's/: test$//p' | LC_ALL=C sort > "$tmp/list"
LC_ALL=C sort "$inventory" > "$tmp/expected"
[[ -s $tmp/expected ]]
diff -u "$tmp/expected" "$tmp/list"
"$executable" --nocapture --test-threads=1 2>&1 | tee "$tmp/output"
(grep -oE 'HS_HELPER_TEST_STARTED [a-zA-Z0-9_:]+' "$tmp/output" || true) | sed 's/^HS_HELPER_TEST_STARTED //' | LC_ALL=C sort > "$tmp/started"
diff -u "$tmp/expected" "$tmp/started"
