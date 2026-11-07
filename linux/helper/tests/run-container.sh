#!/usr/bin/env bash
# Run from the repository root on a disposable Docker host. Inputs must be cached.
set -euo pipefail
image=${HS_HELPER_IMAGE:-rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd}
docker image inspect "$image" >/dev/null
cargo_cache=${HS_HELPER_CARGO_HOME:-${CARGO_HOME:-$HOME/.cargo}}
[[ -d $cargo_cache/registry ]] || { echo 'A local Cargo registry cache is required' >&2; exit 1; }
evidence=$(mktemp -d "${TMPDIR:-/tmp}/hs-helper-evidence.XXXXXXXX")
volume=
complete=0
finish() {
  status=$?
  if (( status != 0 || complete == 0 )); then
    printf 'Failure evidence directory: %s\n' "$evidence" >&2
    if [[ -s $evidence/volume.id ]]; then
      IFS= read -r volume < "$evidence/volume.id" || true
      printf 'Volume ID (may already have been removed): %s\n' "$volume" >&2
    else
      printf 'Volume ID unavailable; inspect Docker for any volume created by this run.\n' >&2
    fi
    for cidfile in "$evidence"/*.cid; do
      [[ -f $cidfile ]] || continue
      printf 'Container ID file: %s (inspect before removing)\n' "$cidfile" >&2
    done
  fi
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "$evidence"
# Write directly to evidence before assigning the ID in the shell. A handled
# signal while Docker runs can then report the ID once the command returns.
docker volume create > "$evidence/volume.id"
IFS= read -r volume < "$evidence/volume.id" || true
[[ -n $volume ]] || { echo 'Docker returned no volume ID.' >&2; exit 1; }
sums=$evidence/sums
printf "image: %s\n" "$image" | tee "$evidence/provenance"
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  printf "checkout HEAD (working tree may differ): %s\n" "$(git rev-parse HEAD)" | tee -a "$evidence/provenance"
fi
docker run --cidfile "$evidence/build.cid" --pull=never --network none --cap-drop=ALL --security-opt no-new-privileges \
  -v "$PWD:/work:ro" -v "$cargo_cache/registry:/cargo/registry:ro" -v "$volume:/target" \
  -w /work/linux/helper -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target "$image" timeout --kill-after=10s 1200s bash -euo pipefail -c '
    exec 3>&1 1>&2
    cargo build --offline --release --locked --bin hotspotshade --manifest-path /work/rust/Cargo.toml
    cargo test --offline --locked --no-run
    mkdir /target/bin
    cp /target/release/hotspotshade /target/bin/hotspotshade
    for name in helper_lifecycle real_engine_demo; do
      candidates=(/target/debug/deps/${name}-*)
      executable=()
      for candidate in "${candidates[@]}"; do
        [[ -f $candidate && -x $candidate && ! $candidate == *.d ]] && executable+=("$candidate")
      done
      [[ ${#executable[@]} == 1 ]] || { echo "Expected exactly one $name executable, found ${#executable[@]}" >&2; exit 1; }
      cp "${executable[0]}" "/target/bin/$name"
    done
    cp /work/linux/helper/tests/verify-run.sh /target/bin/verify-run.sh
    for name in helper_lifecycle real_engine_demo; do cp "/work/linux/helper/tests/inventory/$name" "/target/bin/$name.inventory"; done
    test -x /target/debug/hotspotshade-helper
    rustc --version >&2
    cargo --version >&2
    sha256sum /target/bin/hotspotshade /target/bin/helper_lifecycle /target/bin/real_engine_demo /target/debug/hotspotshade-helper /target/bin/verify-run.sh /target/bin/helper_lifecycle.inventory /target/bin/real_engine_demo.inventory >&3
  ' > "$sums" 2> >(tee "$evidence/build.log" >&2)
docker rm "$(cat "$evidence/build.cid")" >/dev/null
rm "$evidence/build.cid"
cat "$sums"
for name in helper_lifecycle real_engine_demo; do
  docker run --cidfile "$evidence/$name.cid" --pull=never -i --network none --cap-drop=ALL --security-opt no-new-privileges \
    -v "$volume:/target:ro" -e HS_HELPER_INTEGRATION=1 -e HS_REAL_ENGINE=/target/bin/hotspotshade \
    "$image" timeout --kill-after=10s 1200s bash -euo pipefail -c 'bash /target/bin/verify-run.sh "/target/bin/$1" "/target/bin/$1.inventory" /dev/stdin' _ "$name" < "$sums" | tee "$evidence/$name.log"
  docker rm "$(cat "$evidence/$name.cid")" >/dev/null
  rm "$evidence/$name.cid"
done
docker volume rm "$volume" >/dev/null
rm -rf "$evidence"
complete=1
