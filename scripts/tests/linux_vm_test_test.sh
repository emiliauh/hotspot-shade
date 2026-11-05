#!/usr/bin/env bash
# Exercise VM lifecycle handling without contacting Freestyle.
set -euo pipefail
export HOTSPOTSHADE_LINUX_SNAPSHOT=test-snapshot

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-vm-test.XXXXXXXX")
cleanup() {
  for name in npx source.tar.gz calls; do
    if [ -e "$test_dir/$name" ]; then
      unlink "$test_dir/$name"
    fi
  done
  rmdir "$test_dir"
}
trap cleanup EXIT

cat > "$test_dir/npx" <<'EOF'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$4" >> "$HS_VM_TEST_LOG"
if [ "$4" = "${HS_VM_FAIL_PHASE:-}" ]; then
  exit 19
fi
case "$*" in
  *'cat '*) echo 0 ;;
esac
EOF
chmod +x "$test_dir/npx"
touch "$test_dir/source.tar.gz"
export PATH="$test_dir:$PATH"
export HS_VM_TEST_LOG="$test_dir/calls"

check_case() {
  local phase=$1 expected_status=$2 expected_calls=$3 status=0
  : > "$HS_VM_TEST_LOG"
  HS_VM_FAIL_PHASE="$phase" \
    bash "$repo_dir/scripts/linux_vm_test.sh" "$test_dir/source.tar.gz" || status=$?
  if [ "$status" -ne "$expected_status" ]; then
    echo "Unexpected exit status for $phase: $status" >&2
    exit 1
  fi
  local calls
  calls=$(tr '\n' ' ' < "$HS_VM_TEST_LOG")
  if [ "$calls" != "$expected_calls" ]; then
    echo "Unexpected VM lifecycle for $phase: $calls" >&2
    exit 1
  fi
}

check_case none 0 'create fs fs exec exec exec delete '
check_case create 19 'create '
check_case fs 19 'create fs delete '
check_case exec 19 'create fs fs exec delete '
echo "Linux VM lifecycle tests passed."
