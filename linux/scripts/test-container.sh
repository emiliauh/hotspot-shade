#!/bin/sh
# Run the hermetic Electron smoke test, memory check, or responsiveness check
# in a disposable Linux container. The source is mounted read-only. Nothing is
# installed on this host.
#
#   scripts/test-container.sh smoke
#   scripts/test-container.sh memory
#   scripts/test-container.sh responsiveness
#   HOTSPOTSHADE_BIN=/absolute/path/to/linux/hotspotshade scripts/test-container.sh main-engine-warning
#   HOTSPOTSHADE_BIN=/absolute/path/to/linux/hotspotshade scripts/test-container.sh real-engine-window
#
# The container needs network access for the first image build only.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mode=${1:-smoke}
tag=hotspotshade-linux-test:45.2.3

case "$mode" in
  smoke) target=/work/test/smoke-main.js ;;
  a11y) target=/work/test/a11y-main.js ;;
  memory) target=/work/test/memory-main.js ;;
  responsiveness) target=/work/test/responsiveness-main.js ;;
  main-engine-warning) target=/work/test/main-engine-launch.js ;;
  real-engine-window) target=/work/test/real-engine-window-main.js ;;
  *)
    echo "Use smoke, a11y, memory, responsiveness, main-engine-warning, or real-engine-window." >&2
    exit 2
    ;;
esac

if [ "$mode" = main-engine-warning ] || [ "$mode" = real-engine-window ]; then
  engine=${HOTSPOTSHADE_BIN:-}
  case "$engine" in
    /*) ;;
    *) echo "HOTSPOTSHADE_BIN must name an absolute Linux engine path." >&2; exit 2 ;;
  esac
  if [ ! -f "$engine" ] || [ ! -x "$engine" ]; then
    echo "HOTSPOTSHADE_BIN must name an executable file." >&2
    exit 2
  fi
fi

if [ "${HS_TEST_USE_EXISTING_IMAGE:-0}" = 1 ]; then
  docker image inspect "$tag" >/dev/null
else
  docker build -f "$root/scripts/Dockerfile.test" -t "$tag" "$root"
fi

if [ "$mode" = main-engine-warning ]; then
  docker run --rm --init --network none --cap-drop ALL \
    --security-opt seccomp=unconfined --shm-size=512m \
    -v "$root:/work:ro" -v "$engine:/engine/hotspotshade:ro" \
    -e HOTSPOTSHADE_ENGINE=/engine/hotspotshade \
    -e HOTSPOTSHADE_ENGINE_DEMO=1 -e HS_TEST_DEMO_CRASH_WARNING=1 \
    "$tag" bash -lc 'cd /work; status=0; xvfb-run -a /opt/hs-deps/node_modules/.bin/electron test/main-engine-launch.js || status=$?; if [ -f /tmp/hotspotshade-main-engine-report.json ]; then cat /tmp/hotspotshade-main-engine-report.json; else status=1; fi; exit "$status"'
  exit $?
fi

if [ "$mode" = real-engine-window ]; then
  docker run --rm --init --network none --read-only \
    --security-opt seccomp=unconfined --shm-size=512m \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=256m \
    -v "$root:/work:ro" -v "$engine:/engine/hotspotshade:ro" -w /work \
    -e HOME=/tmp -e XDG_CONFIG_HOME=/tmp/hs-config -e XDG_CACHE_HOME=/tmp/hs-cache \
    -e HS_TEST_NETWORK_CONFINED=1 -e HS_REAL_ENGINE_BIN=/engine/hotspotshade \
    "$tag" xvfb-run -a /opt/hs-deps/node_modules/.bin/electron "$target"
  exit $?
fi

docker run --rm --init \
  --security-opt seccomp=unconfined \
  --shm-size=512m \
  -v "$root:/work:ro" \
  "$tag" \
  bash -lc "cd /work && xvfb-run -a /opt/hs-deps/node_modules/.bin/electron $target"
