#!/usr/bin/env bash
# Check the coordinator's help and argument handling without root or signing.
set -euo pipefail
cd "$(dirname "$0")/../.."

swift build --package-path macos/Installer --product hotspotshade-installer-coordinator >/dev/null
bin_dir=$(swift build --package-path macos/Installer --show-bin-path)
coordinator="$bin_dir/hotspotshade-installer-coordinator"

help=$("$coordinator" --help)
[[ "$help" == *'hotspotshade-installer-coordinator self-check'* ]]

result=0
output=$("$coordinator" self-check --help 2>&1) || result=$?
[[ "$result" -eq 2 && "$output" == *'self-check takes no options'* ]]

result=0
output=$("$coordinator" unknown-command --help 2>&1) || result=$?
[[ "$result" -eq 2 && "$output" == *'unknown command: unknown-command'* ]]
echo 'Mac coordinator CLI checks passed.'
