#!/usr/bin/env bash
# Test a reviewed source archive in a disposable Freestyle VM.
#
# Default mode: check, test, clippy, format, and the desktop checks. It creates
# no TUN device and changes no route.
#
# --tunnel: also build the engine and run the ignored Linux tunnel tests as
# root. That mode creates a TUN device, a network namespace, and policy routes
# inside the disposable VM. It must not run on another host.
set -euo pipefail

mode=general
if [ "${1:-}" = "--tunnel" ]; then
  mode=tunnel
  shift
fi
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "Usage: $0 [--tunnel] <reviewed-source.tar.gz>" >&2
  exit 2
fi

source_archive=$1
snapshot_slug=${HOTSPOTSHADE_LINUX_SNAPSHOT:?set HOTSPOTSHADE_LINUX_SNAPSHOT to a prepared Linux VM snapshot}
vm_slug="hotspotshade-test-$(date +%s)-$$"
vm_created=0
runner=$(mktemp "${TMPDIR:-/tmp}/hotspotshade-vm-run.XXXXXXXX")
remote_log=/tmp/hotspotshade-vm-test.log
remote_exit=/tmp/hotspotshade-vm-test.exit

cleanup() {
  rm -f "$runner"
  if [ "$vm_created" -eq 1 ]; then
    npx -y freestyle@latest vm delete "$vm_slug" ||
      echo "Could not delete $vm_slug. Check the Freestyle VM list." >&2
  fi
}
trap cleanup EXIT

cat >"$runner" <<'REMOTE'
#!/usr/bin/env bash
# Runs inside the disposable VM. $1 is the mode.
set -euo pipefail
mode=${1:-general}
root=$(mktemp -d /tmp/hotspotshade-test.XXXXXXXX)
finish() {
  status=$?
  rm -rf "$root"
  echo "$status" >/tmp/hotspotshade-vm-test.exit
  exit "$status"
}
trap finish EXIT
tar -xzf /home/ubuntu/hotspotshade-source.tar.gz -C "$root"
cd "$root"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$HOME/hotspotshade/rust/target"
cargo check --all-targets --locked --manifest-path rust/Cargo.toml
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings
cargo fmt --manifest-path rust/Cargo.toml --check
if [ "$mode" = tunnel ]; then
  cargo build --locked --tests --manifest-path rust/Cargo.toml
  cargo build --locked --manifest-path rust/Cargo.toml
  binary=$(find "$CARGO_TARGET_DIR/debug/deps" -maxdepth 1 -type f \
    -name 'linux_tunnel_vm-*' -perm -u+x | sort | tail -1)
  test -n "$binary"
  sudo -n -E "$binary" --ignored --test-threads=1 --nocapture
  if sudo -n ip -o link show | grep -Eq '(^|: )(hs-tun[0-9]+|hs-host0|hs-src0)(@[^:]*)?:'; then
    echo "a tunnel or test link remained" >&2
    exit 1
  fi
  if sudo -n ip netns list | grep -q '^hs-vm-net'; then
    echo "a test network namespace remained" >&2
    exit 1
  fi
  if sudo -n ip -4 rule show | grep -Eq '^(17000|17001):'; then
    echo "an IPv4 policy rule remained" >&2
    exit 1
  fi
  if sudo -n ip -6 rule show | grep -Eq '^(17000|17001):'; then
    echo "an IPv6 policy rule remained" >&2
    exit 1
  fi
  if [ -n "$(sudo -n ip -4 route show table 700)" ]; then
    echo "an IPv4 tunnel table route remained" >&2
    exit 1
  fi
  if [ -n "$(sudo -n ip -6 route show table 700)" ]; then
    echo "an IPv6 tunnel table route remained" >&2
    exit 1
  fi
else
  cargo test --locked --manifest-path desktop/Cargo.toml
  node --test desktop/tests/fetch_shim.test.mjs desktop/tests/ui_model.test.mjs
  node --test linux/test/*.test.mjs
fi
REMOTE
chmod +x "$runner"

npx -y freestyle@latest vm create \
  --snapshot-id "$snapshot_slug" \
  --slug "$vm_slug" \
  --display-name "HotspotShade Linux test" \
  --ephemeral --no-internet --no-ssh \
  --idle-timeout-seconds 1800
vm_created=1

# The caller must review the archive. Do not send keys, tokens, or captures.
npx -y freestyle@latest vm fs write "$vm_slug" \
  /home/ubuntu/hotspotshade-source.tar.gz "$source_archive"
npx -y freestyle@latest vm fs write "$vm_slug" \
  /home/ubuntu/hotspotshade-vm-run.sh "$runner"

npx -y freestyle@latest vm exec "$vm_slug" --timeout-ms 120000 -- bash -lc \
  "rm -f $remote_log $remote_exit; setsid nohup bash /home/ubuntu/hotspotshade-vm-run.sh $mode > $remote_log 2>&1 < /dev/null & echo STARTED"

deadline=$((SECONDS + 5400))
result=running
while [ "$SECONDS" -lt "$deadline" ]; do
  sleep 10
  if ! result=$(npx -y freestyle@latest vm exec "$vm_slug" --timeout-ms 60000 -- bash -lc \
    "if [ -f $remote_exit ]; then cat $remote_exit; else echo running; fi" 2>/dev/null); then
    result=unreachable
    break
  fi
  if [ "$result" != running ]; then
    break
  fi
done

npx -y freestyle@latest vm exec "$vm_slug" --timeout-ms 120000 -- bash -lc \
  "tail -200 $remote_log" || true

case "$result" in
  0)
    echo "Linux test passed in $vm_slug ($mode mode)."
    ;;
  running)
    echo "Linux test did not finish before the deadline." >&2
    exit 1
    ;;
  unreachable)
    echo "The VM did not answer a poll. Check the log above." >&2
    exit 1
    ;;
  *)
    echo "Linux test failed in $vm_slug ($mode mode)." >&2
    exit 1
    ;;
esac
