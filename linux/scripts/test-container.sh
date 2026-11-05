#!/bin/sh
# Run the hermetic Electron smoke test, memory check, or responsiveness check
# in a disposable Linux container. The source is mounted read-only. Nothing is
# installed on this host.
#
#   scripts/test-container.sh smoke
#   scripts/test-container.sh memory
#   scripts/test-container.sh responsiveness
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
  *)
    echo "Use smoke, a11y, memory, or responsiveness." >&2
    exit 2
    ;;
esac

docker build -f "$root/scripts/Dockerfile.test" -t "$tag" "$root"
docker run --rm --init \
  --security-opt seccomp=unconfined \
  --shm-size=512m \
  -v "$root:/work:ro" \
  "$tag" \
  bash -lc "cd /work && xvfb-run -a /opt/hs-deps/node_modules/.bin/electron $target"
