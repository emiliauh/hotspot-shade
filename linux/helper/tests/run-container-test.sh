#!/usr/bin/env bash
# Run inside a disposable, networkless container from the repository root.
set -euo pipefail
base=$(mktemp -d /tmp/hs-helper-mock.XXXXXXXX)
trap 'rm -rf "$base"' EXIT
mkdir "$base/mockbin" "$base/evidence"
export MOCK_BASE=$base
mkdir -p "$base/cargo/registry"
export HS_HELPER_CARGO_HOME=$base/cargo
cat > ${MOCK_BASE}/mockbin/docker <<'MOCK'
#!/usr/bin/env bash
set -eu
case "$1 $2" in
  'image inspect') exit 0 ;;
  'volume create')
    case "$MOCK_CASE" in
      signal_create) kill -TERM "$PPID" ;;
      signal_int_create) kill -INT "$PPID" ;;
      signal_hup_create) kill -HUP "$PPID" ;;
    esac
    echo "unique-volume-$MOCK_CASE" ;;
  'volume rm')
    echo "$3" >> "$MOCK_BASE/evidence/volumes-$MOCK_CASE"
    [[ "$MOCK_CASE" != signal_volume_rm ]] || kill -TERM "$PPID"
    [[ "$MOCK_CASE" != cleanup ]] ;;
  'rm '* )
    echo "$2" >> "$MOCK_BASE/evidence/removed-$MOCK_CASE"
    [[ "$MOCK_CASE" != container_cleanup ]] ;;
  'run --cidfile')
    args=" $* "
    cidfile=$3
    for required in ' --pull=never ' ' --network none ' ' --cap-drop=ALL ' ' --security-opt no-new-privileges '; do
      [[ $args == *"$required"* ]] || { echo "missing Docker safety argument: $required" >&2; exit 3; }
    done
    file=${MOCK_BASE}/evidence/count-$MOCK_CASE
    count=0; [[ ! -f $file ]] || count=$(cat "$file")
    count=$((count + 1)); echo "$count" > "$file"
    echo "container-$MOCK_CASE-$count" > "$cidfile"
    if [[ "$MOCK_CASE:$count" == signal_run:1 ]]; then kill -TERM "$PPID"; exit 1; fi
    if [[ $count == 1 ]]; then
      [[ $args == *':/work:ro '* && $args == *':/cargo/registry:ro '* && $args == *':/target '* ]] || exit 3
    else
      [[ $args == *':/target:ro '* && $args == *' -e HS_HELPER_INTEGRATION=1 '* && $args == *' /target/bin/verify-run.sh '* ]] || exit 3
    fi
    case "$MOCK_CASE:$count" in build:1|checksum:2|test1:2|test2:3) exit 1 ;; esac
    if [[ $count == 1 ]]; then echo 'digest staged'; fi ;;
  *) echo "unexpected Docker command: $*" >&2; exit 3 ;;
esac
MOCK
chmod +x ${MOCK_BASE}/mockbin/docker
cat > "$base/mockbin/rm" <<'MOCK'
#!/usr/bin/env bash
if [[ ${MOCK_CASE:-} == evidence_cleanup && ${1:-} == -rf && ${2:-} == "$TMPDIR"/hs-helper-evidence.* ]]; then
  exit 1
fi
exec /bin/rm "$@"
MOCK
chmod +x "$base/mockbin/rm"
export PATH=${MOCK_BASE}/mockbin:$PATH TMPDIR=${MOCK_BASE}/evidence
for MOCK_CASE in build checksum test1 test2 cleanup container_cleanup signal_create signal_int_create signal_hup_create signal_run signal_volume_rm evidence_cleanup success; do
  export MOCK_CASE
  if bash linux/helper/tests/run-container.sh > "${MOCK_BASE}/evidence/out-$MOCK_CASE" 2>&1; then
    [[ $MOCK_CASE == success ]] || exit 1
  else
    status=$?
    [[ $MOCK_CASE != success ]] || { cat "${MOCK_BASE}/evidence/out-$MOCK_CASE"; exit 1; }
    case $MOCK_CASE in
      signal_int_create) [[ $status -eq 130 ]] ;;
      signal_hup_create) [[ $status -eq 129 ]] ;;
      signal_*) [[ $status -eq 143 ]] ;;
    esac
    grep -q "Volume ID (may already have been removed): unique-volume-$MOCK_CASE" "${MOCK_BASE}/evidence/out-$MOCK_CASE"
    path=$(sed -n 's/^Failure evidence directory: //p' "${MOCK_BASE}/evidence/out-$MOCK_CASE")
    [[ -d $path && $(cat "$path/volume.id") == "unique-volume-$MOCK_CASE" ]]
    case $MOCK_CASE in
      signal_create|signal_int_create|signal_hup_create) ;;
      *) [[ -f $path/sums ]] ;;
    esac
    case $MOCK_CASE in
      build) retained=1 ;;
      checksum|test1) retained=2 ;;
      test2) retained=3 ;;
      container_cleanup) retained=1 ;;
      cleanup) retained=0 ;;
      signal_create|signal_int_create|signal_hup_create) retained=0 ;;
      signal_run) retained=1 ;;
      signal_volume_rm|evidence_cleanup) retained=0 ;;
    esac
    case $MOCK_CASE in
      signal_volume_rm|evidence_cleanup)
        [[ $(cat "${MOCK_BASE}/evidence/volumes-$MOCK_CASE") == "unique-volume-$MOCK_CASE" ]] ;;
    esac
    if (( retained )); then
      cidfile=$(find "$path" -name '*.cid')
      [[ $(cat "$cidfile") == "container-$MOCK_CASE-$retained" ]]
      grep -q "Container ID file: $cidfile" "${MOCK_BASE}/evidence/out-$MOCK_CASE"
      if [[ $MOCK_CASE != container_cleanup ]]; then
        ! grep -qx "container-$MOCK_CASE-$retained" "${MOCK_BASE}/evidence/removed-$MOCK_CASE" 2>/dev/null
      fi
      [[ ! -e ${MOCK_BASE}/evidence/volumes-$MOCK_CASE ]]
    fi
  fi
done
[[ $(wc -l < "${MOCK_BASE}/evidence/removed-success") -eq 3 ]]
[[ $(cat "${MOCK_BASE}/evidence/volumes-success") == unique-volume-success ]]
# Exercise the same verifier used inside the test containers.
cat > "$base/fake-test" <<'FAKE'
#!/usr/bin/env bash
if [[ ${1:-} == --list ]]; then printf 'alpha: test\nbeta: test\n'; exit; fi
printf 'HS_HELPER_TEST_STARTED alpha\n'
[[ ${VERIFY_CASE:-} == missing ]] || printf 'HS_HELPER_TEST_STARTED beta\n'
[[ ${VERIFY_CASE:-} != extra ]] || printf 'HS_HELPER_TEST_STARTED extra\n'
FAKE
chmod +x "$base/fake-test"
printf 'alpha\nbeta\n' > "$base/inventory"
sha256sum "$base/fake-test" > "$base/sums"
for VERIFY_CASE in success missing extra checksum; do
  export VERIFY_CASE
  if [[ $VERIFY_CASE == checksum ]]; then printf '# changed\n' >> "$base/fake-test"; fi
  if bash linux/helper/tests/verify-run.sh "$base/fake-test" "$base/inventory" "$base/sums" > "$base/verify-$VERIFY_CASE" 2>&1; then
    [[ $VERIFY_CASE == success ]] || { echo "verifier accepted $VERIFY_CASE" >&2; exit 1; }
  else
    [[ $VERIFY_CASE != success ]] || { cat "$base/verify-$VERIFY_CASE"; exit 1; }
  fi
done
echo 'mock phase, Docker arguments, marker, checksum and cleanup checks passed'
