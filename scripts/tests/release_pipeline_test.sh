#!/usr/bin/env bash
# Test the release audit, the checksum manifest, and the CI graph check.
#
# The tests build a small consistent tree, prove that the audit passes it, and
# then break one property at a time to prove that the audit reports it. The
# artifact tests build fake release files and prove that a signed IPA, a
# tampered digest, and a wrong CPU architecture are rejected.
#
# Everything stays hermetic: no build, no network, no route, no credential.
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/hs-release-test.XXXXXXXX")
trap 'chmod -R u+rwX "$work" 2>/dev/null || true; rm -rf "$work"' EXIT

failures=0
out=""
status=0
yaml_check=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

expect_status() {
  # expect_status EXPECTED ACTUAL LABEL
  if [ "$2" -ne "$1" ]; then
    fail "$3 (expected exit $1, got $2)"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

expect_text() {
  # expect_text TEXT LABEL
  if ! printf '%s\n' "$out" | grep -F -- "$1" >/dev/null; then
    fail "$2 (missing: $1)"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

expect_no_text() {
  # expect_no_text TEXT LABEL
  if printf '%s\n' "$out" | grep -F -- "$1" >/dev/null; then
    fail "$2 (unexpected: $1)"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

# A fixture that is not valid YAML cannot prove a YAML bypass. Parse each
# fixture that claims to be valid YAML with a real parser when one is present.
# The audit's own scan stays dependency-free; this check only validates the
# test evidence. Ruby ships with macOS and the GitHub Ubuntu runner.
ruby_yaml=0
if command -v ruby >/dev/null 2>&1 &&
   ruby -ryaml -e 'exit 0' >/dev/null 2>&1; then
  ruby_yaml=1
else
  echo "note: ruby is unavailable; the YAML parser fixture checks are skipped" >&2
fi

expect_yaml_valid() {
  # expect_yaml_valid FILE LABEL
  [ "$ruby_yaml" -eq 1 ] || return 0
  if ! ruby -ryaml -e 'YAML.load_file(ARGV[0])' -- "$1" >/dev/null 2>&1; then
    fail "$2 (the fixture is not valid YAML)"
  fi
}

# The other fixture checks use an independent parser for the format. The
# audit itself stays dependency-free. A missing parser prints a note and skips
# only that evidence check.
ruby_rexml=0
ruby_json=0
cargo_toml=0
plutil_pbx=0
if command -v ruby >/dev/null 2>&1; then
  if ruby -rrexml/document -e 'exit 0' >/dev/null 2>&1; then
    ruby_rexml=1
  else
    echo "note: ruby REXML is unavailable; the plist parser fixture checks are skipped" >&2
  fi
  if ruby -rjson -e 'exit 0' >/dev/null 2>&1; then
    ruby_json=1
  fi
fi
if command -v cargo >/dev/null 2>&1; then
  cargo_toml=1
else
  echo "note: cargo is unavailable; the Cargo metadata fixture checks are skipped" >&2
fi
if command -v plutil >/dev/null 2>&1; then
  plutil_pbx=1
else
  echo "note: plutil is unavailable; the Xcode project fixture checks are skipped" >&2
fi

expect_cargo_package_version() {
  # expect_cargo_package_version MANIFEST NAME VERSION LABEL
  [ "$cargo_toml" -eq 1 ] && [ "$ruby_json" -eq 1 ] || return 0
  got=$(cargo metadata --no-deps --locked --offline --format-version 1 --manifest-path "$1" 2>/dev/null |
    ruby -rjson -e 'j = JSON.parse(STDIN.read); p = j["packages"].find { |x| x["name"] == ARGV[0] }; puts(p ? p["version"] : "")' -- "$2")
  if [ "$got" != "$3" ]; then
    fail "$4 (cargo metadata read '$got', expected '$3')"
  fi
}

expect_rexml_plist_version() {
  # expect_rexml_plist_version FILE KEY VERSION LABEL
  [ "$ruby_rexml" -eq 1 ] || return 0
  if ! ruby -rrexml/document -e '
    doc = REXML::Document.new(File.read(ARGV[0]))
    key = ARGV[1]; want = ARGV[2]; values = []
    doc.elements.each("//key") do |e|
      next unless e.text.to_s.strip == key
      n = e.next_element
      values << (n && n.name == "string" ? n.text.to_s : "")
    end
    exit(values == [want] ? 0 : 1)
  ' -- "$1" "$2" "$3" >/dev/null 2>&1; then
    fail "$4 (REXML did not read exactly one string value $3 for $2)"
  fi
}

expect_rexml_root_plist_version() {
  # expect_rexml_root_plist_version FILE KEY VERSION LABEL
  [ "$ruby_rexml" -eq 1 ] || return 0
  if ! ruby -rrexml/document -e '
    doc = REXML::Document.new(File.read(ARGV[0]))
    key = ARGV[1]; want = ARGV[2]; values = []
    doc.elements.each("/plist/dict/key") do |e|
      next unless e.text.to_s.strip == key
      n = e.next_element
      values << (n && n.name == "string" ? n.text.to_s : "")
    end
    exit(values == [want] ? 0 : 1)
  ' -- "$1" "$2" "$3" >/dev/null 2>&1; then
    fail "$4 (REXML did not read exactly one root dict string value $3 for $2)"
  fi
}

expect_json_root_version() {
  # expect_json_root_version FILE VERSION LABEL
  [ "$ruby_json" -eq 1 ] || return 0
  got=$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0]))["version"].to_s' -- "$1" 2>/dev/null || true)
  if [ "$got" != "$2" ]; then
    fail "$3 (the independent JSON parser read the root version as '$got')"
  fi
}

expect_rexml_appx_version() {
  # expect_rexml_appx_version FILE VERSION LABEL
  [ "$ruby_rexml" -eq 1 ] || return 0
  got=$(ruby -rrexml/document -e '
    doc = REXML::Document.new(File.read(ARGV[0]))
    identity = doc.elements["/Package/Identity"]
    puts(identity ? identity.attributes["Version"].to_s : "")
  ' -- "$1" 2>/dev/null || true)
  if [ "$got" != "$2" ]; then
    fail "$3 (REXML read the Package/Identity Version as '$got')"
  fi
}

expect_plutil_pbx() {
  # expect_plutil_pbx FILE LABEL
  [ "$plutil_pbx" -eq 1 ] || return 0
  if ! plutil -lint "$1" >/dev/null 2>&1; then
    fail "$2 (plutil cannot parse the Xcode project fixture)"
  fi
}

expect_yaml_step_run() {
  # expect_yaml_step_run FILE JOB STEP_NAME SUBSTRING LABEL
  [ "$ruby_yaml" -eq 1 ] || return 0
  got=$(ruby -ryaml -e '
    d = YAML.load_file(ARGV[0])
    steps = d.dig("jobs", ARGV[1], "steps") || []
    s = steps.find { |x| x.is_a?(Hash) && x["name"] == ARGV[2] }
    puts(s && s["run"] ? s["run"] : "")
  ' -- "$1" "$2" "$3")
  case "$got" in
    *"$4"*) ;;
    *) fail "$5 (Psych read the step run value as '$got')" ;;
  esac
}

expect_yaml_last_step_run() {
  # expect_yaml_last_step_run FILE JOB COMMAND LABEL
  [ "$ruby_yaml" -eq 1 ] || return 0
  got=$(ruby -ryaml -e '
    d = YAML.load_file(ARGV[0])
    steps = d.dig("jobs", ARGV[1], "steps") || []
    s = steps.last
    puts(s.is_a?(Hash) && s["run"] ? s["run"] : "")
  ' -- "$1" "$2")
  if [ "$got" != "$3" ]; then
    fail "$4 (Psych read the last step run as '$got')"
  fi
}

expect_yaml_needs_json() {
  # expect_yaml_needs_json FILE JOB EXPECTED_JSON LABEL
  [ "$ruby_yaml" -eq 1 ] && [ "$ruby_json" -eq 1 ] || return 0
  got=$(ruby -ryaml -rjson -e '
    d = YAML.load_file(ARGV[0])
    puts JSON.generate(d.dig("jobs", ARGV[1], "needs"))
  ' -- "$1" "$2")
  if [ "$got" != "$3" ]; then
    fail "$4 (Psych read needs as '$got', expected '$3')"
  fi
}

# ---------------------------------------------------------------------------
# Fixture tree
# ---------------------------------------------------------------------------

# Write one 32-bit little-endian value.
write_le32() {
  value=$1
  printf "\\$(printf '%03o' $((value & 255)))"
  printf "\\$(printf '%03o' $(((value >> 8) & 255)))"
  printf "\\$(printf '%03o' $(((value >> 16) & 255)))"
  printf "\\$(printf '%03o' $(((value >> 24) & 255)))"
}

# Write a small but structurally complete arm64 Mach-O executable. It has one
# LC_SEGMENT_64 that covers the file, one LC_MAIN, and one LC_BUILD_VERSION for
# the requested platform (1 is macOS, 2 is iOS). With REPEAT set to 1 it adds
# a load command with a zero payload, so the command area holds repeated
# 16-byte rows. That proves the audit does not let od collapse a repeated row.
write_test_macho() {
  # write_test_macho FILE [PLATFORM] [REPEAT]
  macho_platform=${2:-1}
  macho_repeat=${3:-0}
  macho_ncmds=3
  macho_sizeofcmds=120
  if [ "$macho_repeat" -eq 1 ]; then
    macho_ncmds=4
    macho_sizeofcmds=168
  fi
  {
    printf '\317\372\355\376'                 # MH_MAGIC_64
    write_le32 16777228                       # CPU_TYPE_ARM64
    write_le32 0                              # CPU_SUBTYPE_ARM64_ALL
    write_le32 2                              # MH_EXECUTE
    write_le32 "$macho_ncmds"
    write_le32 "$macho_sizeofcmds"
    write_le32 2097285                        # flags
    write_le32 0                              # reserved
    # LC_SEGMENT_64 __TEXT covering the whole file.
    write_le32 25
    write_le32 72
    printf '__TEXT'
    dd if=/dev/zero bs=1 count=10 2>/dev/null
    write_le32 0; write_le32 0                # vmaddr
    write_le32 4096; write_le32 0             # vmsize
    write_le32 0; write_le32 0                # fileoff
    write_le32 4096; write_le32 0             # filesize
    write_le32 7                              # maxprot
    write_le32 5                              # initprot
    write_le32 0                              # nsects
    write_le32 0                              # flags
    # LC_MAIN. The entry starts after the header and load commands.
    write_le32 2147483688
    write_le32 24
    write_le32 256; write_le32 0              # entryoff
    write_le32 0; write_le32 0                # stacksize
    # LC_BUILD_VERSION with no build tools.
    write_le32 50
    write_le32 24
    write_le32 "$macho_platform"
    write_le32 917504                         # minos 14.0
    write_le32 917504                         # sdk 14.0
    write_le32 0                              # ntools
    if [ "$macho_repeat" -eq 1 ]; then
      # An unknown 48-byte command with a 40-byte zero payload. The payload
      # spans repeated 16-byte rows, so od without -v would collapse it.
      write_le32 2147483647
      write_le32 48
      dd if=/dev/zero bs=1 count=40 2>/dev/null
    fi
  } > "$1"
  current=$(wc -c < "$1" | tr -d ' ')
  if [ "$current" -lt 4096 ]; then
    dd if=/dev/zero bs=1 count=$((4096 - current)) >> "$1" 2>/dev/null
  fi
  bytes=$(wc -c < "$1" | tr -d ' ')
  [ "$bytes" -eq 4096 ] || fail "the Mach-O fixture must be 4096 bytes, got $bytes"
}

tree=$work/tree
mkdir -p "$tree/.github/workflows" "$tree/scripts/tests" \
  "$tree/rust/src" "$tree/desktop" "$tree/linux/helper" \
  "$tree/macos/HotspotShade.xcodeproj" "$tree/ios/HotspotProxy" \
  "$tree/android/app" "$tree/windows/src/HotspotShade.WinUI2"

printf 'fn main() {}\n' > "$tree/rust/src/main.rs"

cp "$repo_dir/.github/workflows/ci.yml" "$tree/.github/workflows/ci.yml"
cp "$repo_dir/.gitignore" "$tree/.gitignore"
cp "$repo_dir/scripts/release_audit.sh" "$tree/scripts/"
cp "$repo_dir/scripts/release_manifest.sh" "$tree/scripts/"
cp "$repo_dir/scripts/artifact_versions.sh" "$tree/scripts/"
cp "$repo_dir/scripts/macho_version.sh" "$tree/scripts/"
cp "$repo_dir/scripts/tests/artifact_versions_test.sh" "$tree/scripts/tests/"
cp "$repo_dir/scripts/tests/macho_version_test.sh" "$tree/scripts/tests/"
cp "$repo_dir/scripts/release_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/lint_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/rust_macos_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/rust_windows_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/rust_linux_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/desktop_demo_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/desktop_windows_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/winui_demo_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/android_demo_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/ios_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/macos_app_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/release_audit_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/verify_macos_binary_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/verify_ios_ipa_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/verify_macos_app_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/artifact_integrity_job.expected" "$tree/scripts/"
cp "$repo_dir/scripts/ci_graph_check.sh" "$tree/scripts/"
cp "$repo_dir/scripts/build_ipa.sh" "$tree/scripts/"
cp "$repo_dir/scripts/build_mac_app.sh" "$tree/scripts/"

cat > "$tree/rust/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade"
version = "9.9.9"
EOF

cat > "$tree/rust/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "hotspotshade"
version = "9.9.9"
EOF

cat > "$tree/desktop/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade-desktop"
version = "9.9.9"
EOF

cat > "$tree/desktop/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "hotspotshade-desktop"
version = "9.9.9"
EOF

cat > "$tree/linux/helper/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade-helper"
version = "9.9.9"
EOF

cat > "$tree/linux/helper/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "hotspotshade-helper"
version = "9.9.9"
EOF

cat > "$tree/linux/package.json" <<'EOF'
{
  "name": "hotspotshade",
  "version": "9.9.9"
}
EOF

cat > "$tree/linux/package-lock.json" <<'EOF'
{
  "name": "hotspotshade",
  "version": "9.9.9",
  "lockfileVersion": 3
}
EOF

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
AA = {isa = XCBuildConfiguration; name = Release; buildSettings = {MARKETING_VERSION = 9.9.9; PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; }; };
BB = {isa = XCBuildConfiguration; name = Debug; buildSettings = {MARKETING_VERSION = 9.9.9; PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; }; };
EOF

cat > "$tree/ios/HotspotProxy/Info.plist" <<'EOF'
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<string>9.9.9</string>
</dict>
</plist>
EOF

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionCode = 1
        versionName = "9.9.9"
    }
}
EOF

cat > "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" <<'EOF'
<Package>
  <Identity
    Name="HotspotShade"
    Publisher="CN=HotspotShade"
    Version="9.9.9.0" />
</Package>
EOF

audit_status() {
  if [ "$yaml_check" -eq 1 ]; then
    expect_yaml_valid "$tree/.github/workflows/ci.yml" "the workflow fixture for audit_status $* at line ${BASH_LINENO[0]}"
  fi
  set +e
  out=$(sh "$tree/scripts/release_audit.sh" --repo-root "$tree" "$@" 2>&1)
  status=$?
  set -e
}

graph_status() {
  set +e
  out=$(sh "$tree/scripts/ci_graph_check.sh" --workflow "$tree/.github/workflows/ci.yml" 2>&1)
  status=$?
  set -e
}

# ---------------------------------------------------------------------------
# Audit: the consistent tree passes
# ---------------------------------------------------------------------------

audit_status --require-aligned-versions
expect_status 0 "$status" "a consistent tree must pass the strict audit"

audit_status --tag v9.9.9
expect_status 0 "$status" "a matching tag must pass the audit"

cp "$tree/.github/workflows/ci.yml" "$work/ci.bak"
awk '!done && /actions\/checkout@[0-9a-f]+ # v4/ {
  sub(/actions\/checkout@[0-9a-f]+ # v4/, "actions/checkout@v4")
  done = 1
} { print }' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a moving action tag must fail the audit"
expect_text "not pinned to a full commit SHA" "the audit must identify a moving action tag"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

out=$(sh "$repo_dir/scripts/release_audit.sh" --repo-root "$repo_dir" 2>&1) || {
  fail "the release audit must pass on the repository"
  printf '%s\n' "$out" | sed 's/^/    /' >&2
}

# ---------------------------------------------------------------------------
# Tagged source version gate: Cargo tables, lockfile roots, plist comments,
# and Xcode project whitespace and comments
# ---------------------------------------------------------------------------
#
# Each fixture is a semantic near miss: the real version differs from a decoy,
# or the real configuration uses a valid spelling that the old reader missed.
# The independent parser checks show that the fixture means what the audit is
# expected to reject. The audit itself stays dependency-free.

cp "$tree/rust/Cargo.toml" "$work/cargo-semantic.toml"
cp "$tree/rust/Cargo.lock" "$work/cargo-semantic.lock"

cat > "$tree/rust/Cargo.toml" <<'EOF'
[package.metadata]
version = "9.9.9"

[package]
name = "hotspotshade"
version = "1.0.0"
EOF
cat > "$tree/rust/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "hotspotshade"
version = "1.0.0"
EOF
expect_cargo_package_version "$tree/rust/Cargo.toml" hotspotshade 1.0.0 \
  "the Cargo metadata fixture"
audit_status --tag v1.0.0
expect_status 0 "$status" "a [package.metadata] version must not enter the tag gate"
audit_status --tag v9.9.9
expect_status 1 "$status" "the tag gate must read the package version, not metadata"
expect_text "does not match the engine version" "the metadata version bypass must be named"

cat > "$tree/rust/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade"
version = '1.0.0' # a literal TOML string
EOF
expect_cargo_package_version "$tree/rust/Cargo.toml" hotspotshade 1.0.0 \
  "the single-quoted Cargo version fixture"
audit_status --tag v1.0.0
expect_status 0 "$status" "a single-quoted package version must pass the tag gate"

cat > "$tree/rust/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade"
version = { workspace = true }
EOF
audit_status
expect_status 1 "$status" "an unreviewed package version spelling must fail closed"
expect_text "cannot read exactly one [package] version" \
  "the audit must explain an unsupported package version"

cat > "$tree/rust/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade"
description = """
version = "9.9.9"
"""
EOF
audit_status
expect_status 1 "$status" "a version line inside a TOML string must fail closed"
expect_text "cannot read exactly one [package] version" \
  "the audit must not read a package version from a multi-line string"

cat > "$tree/rust/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade"
version = "1.0.0"
EOF
cat > "$tree/rust/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "hotspotshade"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"

[[package]]
name = "hotspotshade"
version = "1.0.0"
dependencies = []
EOF
audit_status --tag v1.0.0
expect_status 0 "$status" "the root lock entry must win over a same-name dependency"

cat > "$tree/rust/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "hotspotshade"
version = "1.0.0"

[[package]]
name = "hotspotshade"
version = "1.0.0"
EOF
audit_status
expect_status 1 "$status" "two root lock entries must fail closed"
expect_text "no unambiguous root package entry" \
  "the audit must explain an ambiguous lockfile root"

cp "$work/cargo-semantic.toml" "$tree/rust/Cargo.toml"
cp "$work/cargo-semantic.lock" "$tree/rust/Cargo.lock"

cp "$tree/ios/HotspotProxy/Info.plist" "$work/info-semantic.bak"
cat > "$tree/ios/HotspotProxy/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
<!-- a comment between keys is not a key -->
<key>CFBundleShortVersionString</key><string>9.9.9</string>
</dict>
</plist>
EOF
expect_rexml_plist_version "$tree/ios/HotspotProxy/Info.plist" CFBundleShortVersionString 9.9.9 \
  "the same-line plist fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "a same-line plist key and string must pass"

cat > "$tree/ios/HotspotProxy/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
<!--
<key>CFBundleShortVersionString</key>
<string>9.9.9</string>
-->
<key>CFBundleShortVersionString</key>
<string>1.0.0</string>
</dict>
</plist>
EOF
expect_rexml_plist_version "$tree/ios/HotspotProxy/Info.plist" CFBundleShortVersionString 1.0.0 \
  "the commented plist key fixture"
audit_status
expect_status 0 "$status" "a commented plist version alone must not fail the plain audit"
expect_text "iOS CFBundleShortVersionString is 1.0.0" \
  "the audit must read the uncommented plist version"
audit_status --require-aligned-versions
expect_status 1 "$status" "a commented plist version must not hide drift"

cat > "$tree/ios/HotspotProxy/Info.plist" <<'EOF'
<plist version="1.0">
<dict>
<key>CFBundleShortVersionString</key>
<string>1.0.0</string>
<key>CFBundleShortVersionString</key>
<string>9.9.9</string>
</dict>
</plist>
EOF
audit_status
expect_status 1 "$status" "a duplicate plist version key must fail closed"
expect_text "cannot read the version: iOS CFBundleShortVersionString" \
  "the audit must explain a duplicate plist key"

cat > "$tree/ios/HotspotProxy/Info.plist" <<'EOF'
<plist version="1.0">
<dict>
<key>CFBundleShortVersionString</key>
<array><string>9.9.9</string></array>
</dict>
</plist>
EOF
audit_status
expect_status 1 "$status" "a plist version that is not a string must fail closed"
expect_text "cannot read the version: iOS CFBundleShortVersionString" \
  "the audit must require a string plist value"

cat > "$tree/ios/HotspotProxy/Info.plist" <<'EOF'
<plist version="1.0">
<dict>
<key>Outer</key>
<dict>
<key>CFBundleShortVersionString</key>
<string>9.9.9</string>
</dict>
</dict>
</plist>
EOF
expect_rexml_plist_version "$tree/ios/HotspotProxy/Info.plist" CFBundleShortVersionString 9.9.9 \
  "the nested plist key fixture"
audit_status
expect_status 1 "$status" "a nested plist version must not supply the root key"
expect_text "cannot read the version: iOS CFBundleShortVersionString" \
  "the audit must not read a nested plist key as the root key"

cat > "$tree/ios/HotspotProxy/Info.plist" <<'EOF'
<plist version="1.0">
<dict>
<key>Outer</key>
<dict>
<key>CFBundleShortVersionString</key>
<string>9.9.9</string>
</dict>
<key>CFBundleShortVersionString</key>
<string>1.0.0</string>
</dict>
</plist>
EOF
expect_rexml_root_plist_version "$tree/ios/HotspotProxy/Info.plist" CFBundleShortVersionString 1.0.0 \
  "the nested plist decoy fixture"
audit_status
expect_status 0 "$status" "a nested plist decoy must not hide the root version"
expect_text "iOS CFBundleShortVersionString is 1.0.0" \
  "the audit must read the root plist version beside a nested decoy"

cp "$work/info-semantic.bak" "$tree/ios/HotspotProxy/Info.plist"

cp "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" "$work/pbx-semantic.bak"
cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
// !$*UTF8*$!
{
 objects = {
  A = {
   isa = XCBuildConfiguration;
   name = "Debug";
   buildSettings = {
    PRODUCT_BUNDLE_IDENTIFIER = "dev.hotspotshade.mac";
    MARKETING_VERSION = "9.9.9";
   };
  };
  B = {
   isa = XCBuildConfiguration;
   name = "Release";
   buildSettings = {
    PRODUCT_BUNDLE_IDENTIFIER = "dev.hotspotshade.mac";
    MARKETING_VERSION = "9.9.9";
   };
  };
 };
}
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the multi-line Xcode project fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "a multi-line quoted Xcode project must pass"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
/* MARKETING_VERSION = 9.9.9; PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; */
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION=1.0.0; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION =  1.0.0 ; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the commented and whitespace Xcode project fixture"
audit_status
expect_status 0 "$status" "a comment must not fail the plain version audit"
expect_text "macOS MARKETING_VERSION is 1.0.0" \
  "the audit must read the uncommented Xcode version"
audit_status --require-aligned-versions
expect_status 1 "$status" "a commented Xcode version must not hide drift"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; OTHER = "MARKETING_VERSION = 9.9.9;"; MARKETING_VERSION = 1.0.0; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 1.0.0; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the quoted Xcode setting fixture"
audit_status
expect_status 0 "$status" "a quoted setting must not fail the plain version audit"
expect_text "macOS MARKETING_VERSION is 1.0.0" \
  "the audit must not read a version from a quoted setting"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
/* A = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; }; */
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; }; };
EOF
audit_status --require-aligned-versions
expect_status 1 "$status" "a commented Xcode configuration must not supply a missing version"
expect_text "cannot verify both macOS app configuration versions" \
  "the audit must require the real Release version"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; MARKETING_VERSION = 9.9.9; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
EOF
audit_status --require-aligned-versions
expect_status 1 "$status" "a duplicate Xcode marketing version must fail closed"
expect_text "cannot verify both macOS app configuration versions" \
  "the audit must reject a duplicate Xcode marketing version"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; "MARKETING_VERSION[sdk=macosx*]" = "1.0.0"; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the conditional MARKETING_VERSION fixture"
audit_status --require-aligned-versions
expect_status 1 "$status" "a conditional Xcode MARKETING_VERSION must fail closed"
expect_text "cannot verify both macOS app configuration versions" \
  "the audit must reject a conditional marketing version it cannot resolve"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; INFOPLIST_KEY_CFBundleShortVersionString = 1.0.0; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the INFOPLIST_KEY version fixture"
audit_status --require-aligned-versions
expect_status 1 "$status" "a generated Info.plist version setting must fail closed"
expect_text "cannot verify both macOS app configuration versions" \
  "the audit must reject an INFOPLIST_KEY version it does not combine"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; "INFOPLIST_KEY_CFBundleShortVersionString[sdk=macosx*]" = "1.0.0"; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the conditional INFOPLIST_KEY version fixture"
audit_status --require-aligned-versions
expect_status 1 "$status" "a conditional INFOPLIST_KEY version setting must fail closed"
expect_text "cannot verify both macOS app configuration versions" \
  "the audit must reject a conditional INFOPLIST_KEY version it cannot resolve"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; GENERATE_INFOPLIST_FILE = YES; INFOPLIST_KEY_CFBundleDisplayName = HotspotShade; MARKETING_VERSION = 9.9.9; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; GENERATE_INFOPLIST_FILE = YES; INFOPLIST_KEY_CFBundleDisplayName = HotspotShade; MARKETING_VERSION = 9.9.9; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the unrelated INFOPLIST_KEY fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "an unrelated INFOPLIST_KEY setting must not fail the audit"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; "ONLY_ACTIVE_ARCH[sdk=macosx*]" = YES; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; "ONLY_ACTIVE_ARCH[sdk=macosx*]" = YES; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the unrelated conditional setting fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "an unrelated conditional build setting must not fail the audit"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; MARKETING_VERSION = 9.9.9; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the configuration-level MARKETING_VERSION fixture"
audit_status --require-aligned-versions
expect_status 1 "$status" "a MARKETING_VERSION outside buildSettings must fail closed"
expect_text "cannot verify both macOS app configuration versions" \
  "the audit must not read a configuration-level marketing version"

cat > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" <<'EOF'
A = {isa = XCBuildConfiguration; name = Debug; PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
B = {isa = XCBuildConfiguration; name = Release; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 9.9.9; }; };
EOF
expect_plutil_pbx "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" \
  "the configuration-level bundle identifier fixture"
audit_status --require-aligned-versions
expect_status 1 "$status" "an ambiguous configuration-level app identity must fail closed"
expect_text "cannot verify both macOS app configuration versions" \
  "the audit must reject a bundle identifier outside buildSettings"

cp "$work/pbx-semantic.bak" "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"

# A JSON root version must not be confused with a nested version, a version
# inside a string, a comment, or a duplicate root key.
cp "$tree/linux/package.json" "$work/package-json.bak"
cp "$tree/linux/package-lock.json" "$work/package-lock.bak"
cat > "$tree/linux/package.json" <<'EOF'
{
  "name": "hotspotshade",
  "description": "a decoy \"version\": \"9.9.9\"",
  "metadata": {
    "version": "9.9.9"
  },
  "version": "1.0.0"
}
EOF
expect_json_root_version "$tree/linux/package.json" 1.0.0 "the nested JSON version fixture"
audit_status
expect_status 0 "$status" "the plain audit must read the JSON root version"
expect_text "version drift: linux/package.json is 1.0.0" \
  "the audit must not select a nested or string version"
audit_status --require-aligned-versions
expect_status 1 "$status" "a nested JSON version must not hide root drift"

cat > "$tree/linux/package.json" <<'EOF'
{
  "name": "hotspotshade",
  "metadata": {
    "version": "9.9.9"
  }
}
EOF
audit_status
expect_status 1 "$status" "JSON without a root version must fail closed"
expect_text "cannot read the version: linux/package.json" \
  "the audit must require a root JSON version"

cat > "$tree/linux/package.json" <<'EOF'
{
  // "version": "9.9.9"
  "version": "1.0.0"
}
EOF
audit_status
expect_status 1 "$status" "a JSON comment decoy must fail closed"
expect_text "cannot read the version: linux/package.json" \
  "the audit must not accept JSON with comments"

cat > "$tree/linux/package.json" <<'EOF'
{
  "version": "1.0.0",
  "version": "9.9.9"
}
EOF
audit_status
expect_status 1 "$status" "a duplicate JSON root version must fail closed"
expect_text "cannot read the version: linux/package.json" \
  "the audit must reject a duplicate root version"

cp "$work/package-json.bak" "$tree/linux/package.json"
cat > "$tree/linux/package-lock.json" <<'EOF'
{
  "name": "hotspotshade",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "version": "9.9.9"
    }
  },
  "version": "1.0.0"
}
EOF
expect_json_root_version "$tree/linux/package-lock.json" 1.0.0 "the nested lockfile version fixture"
audit_status
expect_status 0 "$status" "the plain audit must read the lockfile root version"
expect_text "version drift: linux/package-lock.json is 1.0.0" \
  "the audit must not select a nested lockfile version"
cp "$work/package-lock.bak" "$tree/linux/package-lock.json"

# A Gradle versionName must be the one assignment in android/defaultConfig.
# A comment, a string, or a build-type override must not supply or replace it.
cp "$tree/android/app/build.gradle.kts" "$work/gradle.bak"
cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        // versionName = "9.9.9"
        /* outer /* inner */ versionName = "9.9.9" */
        versionCode = 1
        versionName = "1.0.0"
    }
    buildTypes {
        release {
            versionName = "9.9.9"
        }
    }
}
EOF
audit_status
expect_status 0 "$status" "the plain audit must read the defaultConfig versionName"
expect_text "version drift: Android versionName is 1.0.0" \
  "the audit must not select a comment, string, or nested Gradle version"
audit_status --require-aligned-versions
expect_status 1 "$status" "a comment or nested Gradle version must not hide drift"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        // versionName = "9.9.9"
        versionCode = 1
    }
    buildTypes {
        release {
            versionName = "9.9.9"
        }
    }
}
EOF
audit_status
expect_status 1 "$status" "Gradle without a defaultConfig versionName must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must not take a nested Gradle version"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionName = "1.0.0"
        versionName = "9.9.9"
    }
}
EOF
audit_status
expect_status 1 "$status" "a duplicate Gradle versionName must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject a duplicate Gradle versionName"
cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionName = "9.9.9"
        versionNameSuffix = "-demo"
    }
}
EOF
audit_status
expect_status 1 "$status" "a Gradle versionNameSuffix must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject a versionNameSuffix that changes the built version"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionName = "9.9.9" + "-demo"
    }
}
EOF
audit_status
expect_status 1 "$status" "a Gradle versionName expression must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject a concatenated versionName"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionName = computeVersion()
    }
}
EOF
audit_status
expect_status 1 "$status" "a Gradle versionName function call must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject a computed versionName"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionName = "9.9.9"
    }
    productFlavors {
        free {
            versionName = "1.0.0"
        }
    }
}
EOF
audit_status
expect_status 1 "$status" "a Gradle product flavor must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject a product flavor that can override the version"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    flavorDimensions += "tier"
    defaultConfig {
        versionName = "9.9.9"
    }
}
EOF
audit_status
expect_status 1 "$status" "a Gradle flavor dimension must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject a flavor dimension that enables version overrides"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        // versionNameSuffix = "-demo"
        versionName = "9.9.9"
    }
}
EOF
audit_status --require-aligned-versions
expect_status 0 "$status" "a comment that names versionNameSuffix must not fail the audit"
cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionName = "9.9.9"
    }
}
android.defaultConfig.versionName = "1.0.0"
EOF
audit_status
expect_status 1 "$status" "a dotted Gradle versionName override must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject a dotted versionName that can override defaultConfig"

cat > "$tree/android/app/build.gradle.kts" <<'EOF'
android {
    defaultConfig {
        versionName = "9.9.9"
    }
}
androidComponents {
    onVariants { variant ->
        variant.outputs.forEach { output ->
            output.versionName.set("1.0.0")
        }
    }
}
EOF
audit_status
expect_status 1 "$status" "an Android Components versionName override must fail closed"
expect_text "cannot read the version: Android versionName" \
  "the audit must reject the Android Components DSL that can replace versionName"

cp "$work/gradle.bak" "$tree/android/app/build.gradle.kts"

# The appx Identity Version must be the direct Package child, not a comment,
# another element, or a nested Identity.
cp "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" "$work/appx.bak"
cat > "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Package>
  <!-- <Identity Name="HotspotShade" Version="9.9.9.0" /> -->
  <Properties>
    <DisplayName>HotspotShade</DisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" Version="9.9.9.0" />
  </Dependencies>
  <Identity Name="HotspotShade" Version="1.0.0.0" />
</Package>
EOF
expect_rexml_appx_version "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" 1.0.0.0 \
  "the commented appx Identity fixture"
audit_status
expect_status 0 "$status" "the plain audit must read the real appx Identity"
expect_text "version drift: Windows appx Version is 1.0.0.0" \
  "the audit must not select a comment or another element Version"
audit_status --require-aligned-versions
expect_status 1 "$status" "a comment or another element Version must not hide appx drift"

cat > "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Package>
  <!-- <Identity Name="HotspotShade" Version="9.9.9.0" /> -->
  <Properties>
    <Identity Name="Decoy" Version="9.9.9.0" />
    <DisplayName>HotspotShade</DisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" Version="9.9.9.0" />
  </Dependencies>
  <Identity Name="HotspotShade" Version="1.0.0.0" />
</Package>
EOF
expect_rexml_appx_version "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" 1.0.0.0 \
  "the nested appx Identity fixture"
audit_status
expect_status 1 "$status" "the appx nested Identity decoy must fail closed"
expect_text "cannot read the version: Windows appx Version" \
  "the audit must reject a nested appx Identity"

cat > "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Package>
  <!-- <Identity Name="HotspotShade" Version="9.9.9.0" /> -->
  <Properties>
    <DisplayName>HotspotShade</DisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" Version="9.9.9.0" />
  </Dependencies>
</Package>
EOF
audit_status
expect_status 1 "$status" "appx without a real Identity must fail closed"
expect_text "cannot read the version: Windows appx Version" \
  "the audit must ignore a commented Identity and another element Version"

cat > "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" <<'EOF'
<Package>
  <Identity Name="HotspotShade" Version="9.9.9.0" Version="1.0.0.0" />
</Package>
EOF
audit_status
expect_status 1 "$status" "a duplicate appx Version attribute must fail closed"
expect_text "cannot read the version: Windows appx Version" \
  "the audit must reject a duplicate Identity Version"

cat > "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" <<'EOF'
<Package>
  <Identity Name="HotspotShade" Version="9.9.9.0" />
  <Identity Name="Decoy" Version="1.0.0.0" />
</Package>
EOF
audit_status
expect_status 1 "$status" "a duplicate appx Identity must fail closed"
expect_text "cannot read the version: Windows appx Version" \
  "the audit must reject a second Identity element"

cat > "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest" <<'EOF'
<Package>
  <Identity Name="HotspotShade" Version="9.9.9.0" />
</Package>
<Package>
  <Identity Name="Decoy" Version="1.0.0.0" />
</Package>
EOF
audit_status
expect_status 1 "$status" "a second appx Package root must fail closed"
expect_text "cannot read the version: Windows appx Version" \
  "the audit must reject a second Package root"
cp "$work/appx.bak" "$tree/windows/src/HotspotShade.WinUI2/Package.appxmanifest"

audit_status --require-aligned-versions
expect_status 0 "$status" "the semantic version fixtures must restore cleanly"

# An absent version source is a release blocker in the strict mode that the
# release job uses. A plain audit still reports it as a warning.
mv "$tree/ios/HotspotProxy/Info.plist" "$work/info-missing.bak"
audit_status
expect_status 0 "$status" "a plain audit reports a missing version source as a warning"
expect_text "iOS Info.plist is missing; its version was not checked" \
  "the plain audit must name the missing version source"
audit_status --require-aligned-versions
expect_status 1 "$status" "a strict audit must fail on a missing version source"
expect_text "iOS Info.plist is missing; its version was not checked" \
  "the strict audit must name the missing version source"
mv "$work/info-missing.bak" "$tree/ios/HotspotProxy/Info.plist"
audit_status --require-aligned-versions
expect_status 0 "$status" "the restored version source must pass the strict audit"

# ---------------------------------------------------------------------------
# Audit: one broken property at a time
# ---------------------------------------------------------------------------

audit_status --tag v1.2.3
expect_status 1 "$status" "a tag that does not match the version must fail"
expect_text "does not match the engine version" "the tag failure must explain the mismatch"

for bad_tag in v9.9 v9.9.9.0 v9.9.9-rc1 v9.9.9+build 'v9. 9.9'; do
  audit_status --tag "$bad_tag"
  expect_status 1 "$status" "a nonexact tag must fail: $bad_tag"
done

cp "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" "$work/pbx.bak"
printf 'BB = {isa = XCBuildConfiguration; name = Profile; buildSettings = {PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac; MARKETING_VERSION = 1.0;}; };\n' \
  >> "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"
audit_status --require-aligned-versions
expect_status 1 "$status" "an extra app configuration with another version must fail"
cp "$work/pbx.bak" "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"

sed 's/name = Release; buildSettings = {MARKETING_VERSION = 9.9.9;/name = Release; buildSettings = {/' \
  "$work/pbx.bak" > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"
audit_status --require-aligned-versions
expect_status 1 "$status" "a Release app configuration without a version must fail"

sed 's/name = Release; buildSettings = {MARKETING_VERSION = 9.9.9;/name = Release; buildSettings = {MARKETING_VERSION = 1.0; MARKETING_VERSION = 9.9.9;/' \
  "$work/pbx.bak" > "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"
audit_status --require-aligned-versions
expect_status 1 "$status" "two marketing versions on one configuration must fail"
cp "$work/pbx.bak" "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"

sed -i.bak 's/versionName = "9.9.9"/versionName = "9.9.9-demo"/' "$tree/android/app/build.gradle.kts"
audit_status --require-aligned-versions
expect_status 1 "$status" "a demo suffix must not count as an aligned release version"
sed -i.bak 's/versionName = "9.9.9-demo"/versionName = "9.9.9"/' "$tree/android/app/build.gradle.kts"

cp "$tree/macos/HotspotShade.xcodeproj/project.pbxproj" "$work/pbxproj.bak"
sed -i.bak 's/MARKETING_VERSION = 9.9.9/MARKETING_VERSION = 1.0/' \
  "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"
audit_status
expect_status 0 "$status" "version drift alone must not fail the plain audit"
expect_text "version drift" "the plain audit must warn about version drift"
audit_status --require-aligned-versions
expect_status 1 "$status" "version drift must fail the strict audit"
cp "$work/pbxproj.bak" "$tree/macos/HotspotShade.xcodeproj/project.pbxproj"

cp "$tree/.github/workflows/ci.yml" "$work/ci.bak"

awk '{ print } /^    timeout-minutes: 10$/ && !done { print "    continue-on-error: true"; done = 1 }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "continue-on-error must fail the audit"
expect_text "continue-on-error" "the audit must name continue-on-error"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

# A case variant of continue-on-error is still the same policy key.
for bad_key in Continue-On-Error CONTINUE-ON-ERROR; do
  awk -v key="$bad_key" '{ print } /^    timeout-minutes: 10$/ && !done {
    print "    " key ": true"; done = 1
  }' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
  expect_yaml_valid "$tree/.github/workflows/ci.yml" "the $bad_key fixture"
  audit_status
  expect_status 1 "$status" "a case-variant continue-on-error must fail: $bad_key"
  expect_text "continue-on-error" "the audit must name a case-variant continue-on-error"
done
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

# pull_request_target is never a reviewed trigger, including a case variant or
# an inline flow list.
sed 's/^  pull_request:$/  pull_request_target:/' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the pull_request_target trigger fixture"
audit_status
expect_status 1 "$status" "a pull_request_target trigger must fail"
expect_text "pull_request_target" "the audit must name pull_request_target"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

sed 's/^  pull_request:$/  Pull_Request_Target:/' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the case-variant trigger fixture"
audit_status
expect_status 1 "$status" "a case-variant pull_request_target must fail"
expect_text "pull_request_target" "the audit must read a case-variant trigger"

awk '
  /^on:$/ { print "on: [push, pull_request_target]"; inon = 1; next }
  inon && /^concurrency:$/ { inon = 0; print; next }
  inon { next }
  { print }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the inline trigger list fixture"
audit_status
expect_status 1 "$status" "an inline pull_request_target trigger must fail"
expect_text "pull_request_target" "the audit must read an inline trigger list"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

sed 's/^  push:$/  Push:/' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the case-variant trigger name fixture"
audit_status
expect_status 1 "$status" "an ambiguous trigger case variant must fail"
expect_text "ambiguous case variant of trigger" "the audit must reject a case-variant trigger name"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

sed 's/^  workflow_dispatch:$/  workflow_run:/' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the unknown trigger fixture"
audit_status
expect_status 1 "$status" "an unreviewed trigger must fail"
expect_text "unsupported trigger workflow_run" "the audit must name an unsupported trigger"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

# A comment between needs entries is not the end of the list.
awk '1; /^      - lint$/ { print "  # a comment between needs entries" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the needs comment fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "a comment inside the needs list must not hide later edges"

# A blank line inside the needs list is not the end of the list either. The
# exact block matcher treats the added blank as a policy change, so the audit
# fails for that reason; the prerequisite check must still read every edge.
awk '1; /^      - lint$/ { print "" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the needs blank line fixture"
audit_status --require-aligned-versions
expect_status 1 "$status" "a blank line inside needs must not silently remove edges"
expect_text "differs from the reviewed policy block" \
  "the blank line must be reported as a reviewed-block change"
expect_no_text "does not wait for" \
  "the prerequisite check must read edges after a blank line"
graph_status
expect_status 0 "$status" "the graph check must skip a blank line inside needs"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

sed -i.bak '/^      - artifact-integrity$/d' "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a release job that skips a required job must fail"
expect_text "does not wait for" "the audit must name the missing prerequisite"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

awk -v secret_line='          TOKEN: ${{ secrets.RELEASE_TOKEN }}' '
  { print }
  /^      - uses: actions\/checkout@[0-9a-f]+([[:space:]]|$)/ && !done {
    print "        env:"
    print secret_line
    done = 1
  }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a repository secret in the workflow must fail"
expect_text "reads a repository secret" "the audit must name the secret"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

awk -v secret_line='          TOKEN: ${{ secrets["RELEASE_TOKEN"] }}' '
  { print }
  /^      - uses: actions\/checkout@[0-9a-f]+([[:space:]]|$)/ && !done {
    print "        env:"
    print secret_line
    done = 1
  }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a bracket-style repository secret must fail"
expect_text "reads a repository secret" "the audit must recognize bracket-style secrets"

awk '1; /^  rust-windows:$/ { print "    permissions: write-all" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a job with write-all must fail"
expect_text "write-all permissions" "the audit must identify write-all"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

sed -i.bak '/^          retention-days: 14$/d' "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "an upload without a retention limit must fail"
expect_text "retention" "the audit must name the retention limit"
cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"

: > "$tree/leak.p12"
audit_status
expect_status 1 "$status" "signing material in the tree must fail the audit"
expect_text "leak.p12" "the audit must name the leaked file"
rm -f "$tree/leak.p12"

audit_status --require-aligned-versions
expect_status 0 "$status" "the restored tree must pass again"

# ---------------------------------------------------------------------------
# Audit: YAML spellings that could bypass the pin and permission policy
# ---------------------------------------------------------------------------

ci_file=$tree/.github/workflows/ci.yml
cp "$ci_file" "$work/ci.bak"

# A quoted uses key with an unpinned action must not hide the reference.
awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
  print "      - \047uses\047 : actions/checkout@v4"
  done = 1
  next
} { print }' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a single-quoted uses key with a moving tag must fail"
expect_text "not pinned to a full commit SHA" "the audit must read a single-quoted uses key"

awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
  print "      - \"uses\" : actions/checkout@v4"
  done = 1
  next
} { print }' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a double-quoted uses key with a moving tag must fail"
expect_text "not pinned to a full commit SHA" "the audit must read a double-quoted uses key"

# A quoted value that holds a comment must not be read as a pinned reference.
awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
  line = $0
  sub(/^      - uses: /, "", line)
  sub(/ # v4$/, "", line)
  print "      - uses: \"" line " # v4\""
  done = 1
  next
} { print }' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a quoted action reference with trailing text must fail"
expect_text "unsupported or empty action reference" "the audit must not accept a quoted reference with trailing text"

# A flow mapping is valid YAML and must not hide an action reference.
awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
  print "      - { uses: actions/checkout@v4 }"
  done = 1
  next
} { print }' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a flow-mapping uses key with a moving tag must fail"
expect_text "unsupported YAML flow collection" "the audit must reject a flow-mapping uses key"

# A space before the key colon is valid YAML.
awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
  print "      - uses : actions/checkout@v4"
  done = 1
  next
} { print }' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a spaced uses key with a moving tag must fail"
expect_text "not pinned to a full commit SHA" "the audit must read a spaced uses key"

{
  cat "$work/ci.bak"
  printf '  zz-spaced:\n'
  printf '    runs-on: ubuntu-latest\n'
  printf '    steps:\n'
  printf '      - uses : actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n'
} > "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "a spaced uses key with a full commit pin must still pass"

# An explicit YAML key is valid YAML and must not hide an action reference.
awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
  print "      - ? uses"
  print "        : actions/checkout@v4"
  done = 1
  next
} { print }' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an explicit uses key with a moving tag must fail"
expect_text "unsupported YAML explicit key" "the audit must reject an explicit uses key"

# A block scalar on a sequence item must not hide a sibling key.
awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
  print "      - run: |"
  print "          echo hi"
  print "        uses: actions/checkout@v4"
  done = 1
  next
} { print }' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a block scalar on a step line must not hide a sibling uses key"
expect_text "action reference is not pinned" "the audit must still read a sibling key after a block scalar"

# A permission on a job other than release, in a spelling the old text match
# missed, must fail.
awk '1; /^  rust-windows:$/ {
  print "    permissions:"
  print "      contents:  write"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a non-release job with a spaced contents write must fail"
expect_text "job rust-windows grants contents: write" "the audit must read a spaced contents write"

awk '1; /^  rust-windows:$/ {
  print "    permissions:"
  print "      \"contents\" : write"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a non-release job with a quoted contents write must fail"
expect_text "job rust-windows grants contents: write" "the audit must read a quoted contents key"

awk '1; /^  rust-windows:$/ {
  print "    \"permissions\" : \"write-all\""
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a quoted write-all permission must fail"
expect_text "write-all permissions" "the audit must read a quoted write-all value"

awk '1; /^  rust-windows:$/ {
  print "    permissions:"
  print "      id-token: write"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a non-release job with id-token write must fail"
expect_text "job rust-windows grants id-token: write" "the audit must reject an OIDC write scope"

sed 's/^  contents: read$/  contents: write/' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a top-level contents write must fail"
expect_text "job <top-level> grants contents: write" "the audit must attribute a top-level write"

awk '1; /^  rust-windows:$/ {
  print "    permissions: { contents: write }"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an inline permission map with write must fail"
expect_text "inline permissions mapping grants write access" "the audit must reject an inline write map"

awk '1; /^  rust-windows:$/ {
  print "    permissions:"
  print "      ? contents"
  print "      : write"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an explicit permission key with write must fail"
expect_text "unsupported YAML explicit key" "the audit must reject an explicit permission key"

awk '1; /^  rust-windows:$/ {
  print "    permissions:"
  print "      \"cont\\u0065nts\": write"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a YAML escape in a permission key must fail"
expect_text "unsupported YAML escape in a key" "the audit must reject a YAML key escape"

# An anchored job header must not shift its permission grant onto another job.
awk '1; /^jobs:$/ {
  print "  # ci-stage: test"
  print "  anchored: &anchored"
  print "    permissions:"
  print "      contents: write"
  print "    runs-on: ubuntu-latest"
  print "    steps: []"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an anchored job header must fail"
expect_text "unsupported job header" "the audit must reject a job header it cannot attribute"

# A flow-mapping job body must not hide a permission grant.
awk '1; /^jobs:$/ {
  print "  # ci-stage: test"
  print "  flowjob:"
  print "    {permissions: {contents: write}, runs-on: ubuntu-latest, steps: []}"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a flow-mapping job body must fail"
expect_text "unsupported YAML flow collection" "the audit must reject a flow-mapping job body"

# A comment that looks like an action or a permission must not be read as one.
awk '1; /^  rust-windows:$/ {
  print "  # - uses: actions/checkout@v4"
  print "  # contents: write"
}' "$work/ci.bak" > "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "a comment that looks like a policy entry must not fail the audit"

# Quoted keys and a spaced colon at the top level still describe a read-only
# default token.
awk '
/^permissions:$/ { print "\"permissions\" :"; next }
/^  contents: read$/ { print "  \"contents\"  :  read"; next }
{ print }' "$work/ci.bak" > "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "a quoted read-only default permission must pass"

# ---------------------------------------------------------------------------
# Audit: valid-YAML spellings that hid a write or an unpinned action
# ---------------------------------------------------------------------------
#
# Every fixture below parses as YAML and gives GitHub a real job permission or
# action reference. A text scanner cannot read every spelling, so each fixture
# must produce a FAIL line rather than a pass.
yaml_check=1

# A flow-mapping job body is valid at any indentation. At indent 6 the older
# scan never attributed it to a job, so the write was invisible.
awk '
  /^  rust-windows:$/ {
    print
    print "      {permissions: {contents: write}, runs-on: windows-latest, timeout-minutes: 30, steps: []}"
    injob = 1; next
  }
  injob && /^  [a-zA-Z0-9_-]+:$/ { injob = 0 }
  injob { next }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a flow-mapping job body at indent 6 must fail"
expect_text "unsupported YAML flow collection" "the audit must reject a flow collection in a node position"

# A flow mapping can also carry the action as the value of a normal key.
awk '
  /^  rust-windows:$/ {
    print
    print "    runs-on: windows-latest"
    print "    timeout-minutes: 30"
    print "    steps: [{uses: actions/checkout@v4}]"
    injob = 1; next
  }
  injob && /^  [a-zA-Z0-9_-]+:$/ { injob = 0 }
  injob { next }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a flow-mapping action value must fail"
expect_text "unsupported YAML flow mapping" "the audit must reject a flow mapping in a value"

# A single-pair flow sequence names the action without braces.
awk '
  /^  rust-windows:$/ {
    print
    print "    runs-on: windows-latest"
    print "    timeout-minutes: 30"
    print "    steps: [uses: actions/checkout@v4]"
    injob = 1; next
  }
  injob && /^  [a-zA-Z0-9_-]+:$/ { injob = 0 }
  injob { next }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a single-pair flow action must fail"
expect_text "unsupported YAML spelling for an action reference" "the audit must reject a single-pair flow action"

# A YAML tag on an explicit key still names an action reference.
awk '1; /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ && !done {
  print "      - ? !!str uses"
  print "        : actions/checkout@v4"
  done = 1
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a tagged explicit uses key must fail"
expect_text "unsupported YAML explicit key" "the audit must reject a tagged explicit action key"

# A block-scalar or folded explicit key can spell `permissions` or `uses`.
awk '1; /^  rust-windows:$/ {
  print "    ? |-"
  print "      permissions"
  print "    : write-all"
  print "    ? >-"
  print "      uses"
  print "    : actions/checkout@v4"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "block-scalar explicit keys must fail"
expect_text "unsupported YAML explicit key" "the audit must reject a folded or block-scalar explicit key"

# A job body may sit at any indentation. At indent 6 an explicit tagged key was
# not read, so a job-level write-all was missed.
awk '
  /^  rust-windows:$/ { print; injob = 1; next }
  injob && /^  [^ ]/ { injob = 0 }
  injob && /^ +/ { print "  " $0; next }
  { print }
' "$work/ci.bak" > "$work/indented6.yml"
awk '
  /^      name: Rust \(Windows\) type check and test$/ {
    print
    print "      ? !!str permissions"
    print "      : write-all"
    next
  }
  { print }
' "$work/indented6.yml" > "$ci_file"
audit_status
expect_status 1 "$status" "a tagged explicit permission at job body indent 6 must fail"
expect_text "unsupported YAML explicit key" "the audit must reject an explicit permission key at an odd indent"

# A normal permission mapping at an odd indent must still be attributed to its
# job, so the write is named rather than silently accepted.
awk '
  /^  rust-windows:$/ { print; injob = 1; next }
  injob && /^  [^ ]/ { injob = 0 }
  injob && /^    / { print substr($0, 2); next }
  { print }
' "$work/ci.bak" > "$work/indented3.yml"
awk '
  /^   name: Rust \(Windows\) type check and test$/ {
    print
    print "   permissions:"
    print "     contents: write"
    next
  }
  { print }
' "$work/indented3.yml" > "$ci_file"
audit_status
expect_status 1 "$status" "a job body at indent 3 with a write must fail"
expect_text "job rust-windows grants contents: write" "the audit must attribute an oddly indented permission"

# A multi-line double-quoted scalar can fold a fake block-scalar header at any
# indentation. The older block skip then hid the real keys after the scalar.
awk '
  /^  rust-windows:$/ { injob = 1 }
  injob && /^  [^ ]/ && !/^  rust-windows:$/ { injob = 0 }
  /^    name: Rust \(Windows\) type check and test$/ {
    print "    name: \"Rust (Windows)"
    print "   y: |"
    print "     type check\""
    print "    permissions:"
    print "      contents: write"
    next
  }
  injob && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ && !done {
    sub(/actions\/checkout@[0-9a-f]+ # v4/, "actions/checkout@v4")
    done = 1
  }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a multi-line quoted scalar must not hide a write and an unpinned action"
expect_text "unsupported multi-line quoted scalar" "the audit must reject a multi-line quoted scalar"
expect_text "job rust-windows grants contents: write" "the audit must read the permission after the quoted scalar"
expect_text "actions/checkout@v4" "the audit must read the action after the quoted scalar"

# The same fold works with single quotes.
awk '
  /^    name: Rust \(Windows\) type check and test$/ {
    print "    name: \047Rust (Windows)"
    print "   y: |"
    print "     type check\047"
    print "    permissions:"
    print "      contents: write"
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a multi-line single-quoted scalar must not hide a write"
expect_text "unsupported multi-line quoted scalar" "the audit must reject a multi-line single-quoted scalar"

# A duplicate job key can hide the steps list that GitHub reads. The fixture
# puts the hidden step in the second steps key, which Psych keeps.
awk '
  /^  rust-windows:$/ { print; injob = 1; next }
  injob && /^        run: cargo clippy --all-targets --locked -- -D warnings$/ {
    print
    print "    steps:"
    print "      - run: echo hidden"
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_last_step_run "$ci_file" rust-windows "echo hidden" \
  "the duplicate steps fixture"
audit_status
expect_status 1 "$status" "a duplicate job steps key must fail"
expect_text "duplicate key steps in job rust-windows" \
  "the audit must name a duplicate job key"

# A duplicate step key can hide the command that GitHub reads.
awk '
  /^  rust-windows:$/ { injob = 1 }
  injob && /^        run: cargo test --locked$/ {
    print
    print "        run: echo hidden"
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_step_run "$ci_file" rust-windows Test "echo hidden" \
  "the duplicate step run fixture"
audit_status
expect_status 1 "$status" "a duplicate step run key must fail"
expect_text "duplicate key run in a step" \
  "the audit must name a duplicate step key"

# A plain scalar can continue on an indented line. Psych folds the hidden
# text into the command, so the audit must reject the spelling.
awk '
  /^  rust-windows:$/ { injob = 1 }
  injob && /^        run: cargo check --all-targets --locked$/ {
    print "        run: cargo check --all-targets --locked \\"
    print "            && echo hidden"
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_step_run "$ci_file" rust-windows "Type check (all targets)" "echo hidden" \
  "the plain scalar continuation fixture"
audit_status
expect_status 1 "$status" "a multi-line plain scalar must fail"
expect_text "unsupported plain scalar continuation" \
  "the audit must reject a plain scalar continuation"

# Windows reads environment names without case, so Path is PATH.
for env_key in Path path PATHEXT ComSpec; do
  awk -v env_key="$env_key" '
    /^  rust-windows:$/ { injob = 1; print; next }
    injob && /^      - name: Type check \(all targets\)$/ {
      print
      print "        env:"
      print "          " env_key ": C:\\\\replaced"
      injob = 0
      next
    }
    { print }
  ' "$work/ci.bak" > "$ci_file"
  audit_status
  expect_status 1 "$status" "a case-variant command environment must fail: $env_key"
  expect_text "environment variable $env_key may replace a command" \
    "the audit must read a Windows environment name without case"
done

# A path input in with: is not an environment variable.
{
  cat "$work/ci.bak"
  printf '  zz-with-input:\n'
  printf '    runs-on: ubuntu-latest\n'
  printf '    steps:\n'
  printf '      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4\n'
  printf '        with:\n'
  printf "          node-version: '22'\n"
  printf '          path: rust/target/release/hotspotshade\n'
} > "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "a with path input must not be read as an environment name"

# Text inside a real block scalar is shell content, not workflow structure.
{
  cat "$work/ci.bak"
  printf '  zz-scalar:\n'
  printf '    runs-on: ubuntu-latest\n'
  printf '    steps:\n'
  printf '      - name: Harmless\n'
  printf '        run: |\n'
  printf '          uses: actions/checkout@v4\n'
  printf '          permissions: write-all\n'
} > "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "keys inside a block scalar must not be read as policy"

# A single-pair flow sequence with a quoted key names an action without a
# flow mapping. The quote masks the key from the spelling check, so the flow
# sequence itself must fail closed.
awk '
  /^  rust-windows:$/ { print; injob = 1; next }
  injob && /^  [a-zA-Z0-9_-]+:$/ { injob = 0 }
  injob && /^    steps:$/ { print "    steps: [\"uses\" : actions/checkout@v4]"; skip = 1; next }
  skip && /^      / { next }
  skip { skip = 0 }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a quoted key in a flow-sequence action must fail"
expect_text "unsupported YAML flow mapping in a sequence" "the audit must reject a flow-sequence action pair"

# A lone CR is a YAML line break. The LF scan would read the hidden text as
# part of the previous value.
awk '
  BEGIN { cr = sprintf("%c", 13) }
  !done && $0 == "  rust-windows:" {
    print
    print "    runs-on: windows-latest" cr "    permissions:" cr "      contents: write"
    done = 1
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a lone CR must not hide workflow text"
expect_text "unsupported carriage return line break" "the audit must reject a CR line break"

# A bare secrets context and toJSON(secrets) leak every secret.
for secret_line in '          TOKEN: ${{ secrets }}' '          TOKEN: ${{ toJSON(secrets) }}'; do
  awk -v secret_line="$secret_line" '
    { print }
    /^      - uses: actions\/checkout@[0-9a-f]+([[:space:]]|$)/ && !done {
      print "        env:"
      print secret_line
      done = 1
    }
  ' "$work/ci.bak" > "$ci_file"
  expect_yaml_valid "$ci_file" "the secrets expression fixture"
  audit_status
  expect_status 1 "$status" "a bare secrets expression must fail: $secret_line"
  expect_text "reads a repository secret" "the audit must recognize every secrets expression"
done

# A YAML plain scalar can fold an expression across lines. A line-at-a-time
# scan cannot read it, so it must fail instead of passing the expression.
awk '
  { print }
  /^      - uses: actions\/checkout@[0-9a-f]+([[:space:]]|$)/ && !done {
    print "        env:"
    print "          TOKEN: ${{"
    print "            secrets.RELEASE_TOKEN }}"
    done = 1
  }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the folded secrets expression fixture"
audit_status
expect_status 1 "$status" "a folded secrets expression must fail"
expect_text "unsupported multi-line expression" "the audit must reject an expression it cannot read on one line"

# A YAML escape can spell `${{` and hide the expression from a text match.
awk '
  {
    print
  }
  /^      - uses: actions\/checkout@[0-9a-f]+([[:space:]]|$)/ && !done {
    print "        env:"
    print "          TOKEN: \"\\u0024\\u007b\\u007b secrets.RELEASE_TOKEN }}\""
    done = 1
  }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an escaped expression brace must fail"
expect_text "unsupported YAML escape in a quoted value" "the audit must reject a YAML escape that can spell an expression"

# A reusable workflow can inherit every repository secret.
awk '
  { print }
  /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ && !done {
    print "      - uses: octo/example/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567"
    print "        secrets: inherit"
    done = 1
  }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a reusable workflow that inherits secrets must fail"
expect_text "passes secrets to a reusable workflow" "the audit must reject secrets: inherit"

# A quoted YAML escape can spell the v-tag trigger.
awk '
  $0 == "    if: startsWith(github.ref, \047refs/tags/v\047)" {
    print "    if: \"\\u0073tartsWith(github.ref, \047refs/tags/v\047)\""
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an escaped v-tag trigger must fail"
expect_text "unsupported YAML escape in a quoted value" "the audit must reject an escaped trigger value"

# The same escape in a key can hide a job condition from a lighter check.
awk '1; /^  verify-ios-ipa:$/ { print "    \"\\u0069f\": always()" }' \
  "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an escaped job condition key must fail"
expect_text "unsupported YAML escape in a key" "the audit must reject an escaped condition key"

# A stage comment at the job-key indentation is a comment, not the end of the
# job. Extra release steps after it must still fail the reviewed block match.
awk '
  /^            release\/PROVENANCE.txt$/ {
    print
    print "  # ci-stage: release"
    print "      - name: Publish a second time"
    print "        run: gh release upload hidden extra"
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the stage-comment release fixture"
audit_status
expect_status 1 "$status" "a stage comment must not hide release steps"
expect_text "differs from the reviewed policy block" "the audit must read steps after a stage comment"

# Workflow-level defaults can replace the shell or working directory of every
# run step without changing any reviewed job block.
awk '
  /^jobs:$/ {
    print "defaults:"
    print "  run:"
    print "    shell: \"/bin/true {0}\""
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the workflow-level defaults fixture"
audit_status
expect_status 1 "$status" "workflow-level defaults must fail the audit"
expect_text "workflow-level defaults" "the audit must reject a replaced default shell"

# Workflow-level env is inherited by release and every verification job.
awk '1; /^env:$/ { print "  PATH: /tmp/replaced" }' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the workflow-level PATH fixture"
audit_status
expect_status 1 "$status" "a workflow-level PATH entry must fail"
expect_text "workflow-level env may not set PATH" "the audit must reject a replaced command path"

# An inline workflow env mapping cannot be checked entry by entry.
awk '
  /^env:$/ { print "env: { CARGO_TERM_COLOR: never }"; inside = 1; next }
  inside && /^  / { next }
  { inside = 0; print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the inline workflow env fixture"
audit_status
expect_status 1 "$status" "an inline workflow env mapping must fail"
expect_text "unsupported workflow-level env mapping" "the audit must reject an inline workflow env"

# A second YAML document can make a policy check and GitHub read different
# trees. Reject the document marker instead of guessing which one runs.
{ cat "$work/ci.bak"; printf '\n---\nname: Other\njobs:\n  hidden:\n    runs-on: ubuntu-latest\n    steps: []\n'; } > "$ci_file"
expect_yaml_valid "$ci_file" "the second-document fixture"
audit_status
expect_status 1 "$status" "a second YAML document must fail"
expect_text "unsupported YAML document marker" "the audit must reject a second YAML document"

# Two job keys with the same id are ambiguous in YAML and can make a policy
# check and GitHub read different jobs.
yaml_check=0
{ cat "$work/ci.bak"; printf '\n  release:\n    runs-on: ubuntu-latest\n'; } > "$ci_file"
audit_status
expect_status 1 "$status" "a duplicate job id must fail"
expect_text "duplicate job id" "the audit must name the duplicate job"

# A duplicate top-level key has the same ambiguity for jobs, env, and
# permissions.
{ cat "$work/ci.bak"; printf '\njobs:\n  hidden:\n    runs-on: ubuntu-latest\n    steps: []\n'; } > "$ci_file"
audit_status
expect_status 1 "$status" "a duplicate top-level key must fail"
expect_text "duplicate top-level key" "the audit must name the duplicate top-level key"
yaml_check=1

# A fake verification command inside a block scalar is data, not a step. The
# reviewed block is the gate, not a text match for the command.
awk '
  /^  verify-ios-ipa:$/ {
    print "  verify-ios-ipa:"
    print "    name: Verify iOS IPA artifact"
    print "    needs: [ios]"
    print "    runs-on: ubuntu-latest"
    print "    timeout-minutes: 10"
    print "    steps:"
    print "    - name: Skip the audit"
    print "      run: |"
    print "        cat >/dev/null <<\047EOF\047"
    print "        run: sh scripts/release_audit.sh --artifacts artifact"
    print "        EOF"
    skip = 1
    next
  }
  skip && /^  [a-zA-Z0-9_-]+:$/ { skip = 0 }
  skip { next }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a command inside a block scalar must not satisfy verification"
expect_text "differs from the reviewed policy block" "the audit must compare the exact verification block"

# A step shell can ignore the checked command.
awk '1; /^  verify-macos-binary:$/ {
  print "    defaults:"
  print "      run:"
  print "        shell: \"/bin/true {0}\""
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a verification step shell override must fail"
expect_text "differs from the reviewed policy block" "the audit must reject a changed verification shell"

# An extra step can replace the checked script before the real command runs.
awk '1; /^      - name: Audit the downloaded IPA$/ {
  print "      - name: Disable the audit"
  print "        run: cp /dev/null scripts/release_audit.sh"
}' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a step that rewrites the audit script must fail"
expect_text "differs from the reviewed policy block" "the audit must reject an added preparation step"

# A comment is not a retention limit.
awk 'BEGIN { removed = 0 }
  {
    if (!removed && $0 == "          retention-days: 14") { removed = 1; next }
    print
  }
' "$work/ci.bak" > "$work/noretain.yml"
awk '1; /^  rust-windows:$/ { print "    # retention-days: 14" }' \
  "$work/noretain.yml" > "$ci_file"
audit_status
expect_status 1 "$status" "a comment must not supply a retention limit"
expect_text "retention" "the audit must report the missing retention limit"

# Text in a block scalar is not a retention limit either.
awk '1; /^      - name: Clippy \(Windows code\)$/ {
  print "      - name: Harmless"
  print "        run: |"
  print "          retention-days: 14"
}' "$work/noretain.yml" > "$ci_file"
audit_status
expect_status 1 "$status" "a block scalar must not supply a retention limit"
expect_text "retention" "the audit must ignore retention text in a block scalar"

# An anchor in a value can move reviewed text to an unchecked node.
sed 's/^    runs-on: windows-latest$/    runs-on: \&runner windows-latest/' \
  "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "an anchored job value must fail"
expect_text "anchor or alias in a value" "the audit must reject an anchor in a value"

# A quoted merge key is still a merge key, and its value can move a mapping
# into a job without a visible key.
awk '1; /^  rust-windows:$/ { print "    \"<<\": {runs-on: windows-latest}" }' \
  "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a quoted merge key must fail"
expect_text "unsupported YAML merge key" "the audit must reject a quoted merge key"

# A shell redirect is not an anchor.
{
  cat "$work/ci.bak"
  printf '  zz-env:\n'
  printf '    runs-on: ubuntu-latest\n'
  printf '    env:\n'
  printf '      CHECK: true 2>&1\n'
  printf '    steps:\n'
  printf '      - run: echo ok\n'
} > "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "a shell redirect value must still pass"

cp "$work/ci.bak" "$ci_file"

# ---------------------------------------------------------------------------
# Audit: a top-level block scalar must not supply the reviewed job blocks
# ---------------------------------------------------------------------------
#
# A top-level block scalar is valid YAML. Its content can hold a line at the
# job-key indentation, complete with a reviewed job body, before the real
# jobs mapping. A scanner that reads the first raw matching header anywhere
# in the file would compare the decoy and miss the real job. The decoy below
# holds every reviewed block, and every real job gets a comment that makes it
# differ from its expected block. The fixture is parsed by Psych so it cannot
# pass as a YAML bypass if it is malformed.

decoy=$work/decoy-jobs.yml
: > "$decoy"
for spec in \
  'release:release_job' \
  'rust-macos:rust_macos_job' \
  'ios:ios_job' \
  'macos-app:macos_app_job' \
  'release-audit:release_audit_job' \
  'verify-macos-binary:verify_macos_binary_job' \
  'verify-ios-ipa:verify_ios_ipa_job' \
  'verify-macos-app:verify_macos_app_job' \
  'artifact-integrity:artifact_integrity_job'; do
  job=${spec%%:*}
  expected=${spec#*:}
  {
    printf '  %s:\n' "$job"
    cat "$repo_dir/scripts/$expected.expected"
  } >> "$decoy"
done

awk -v decoy="$decoy" '
  NR == 1 {
    print "name: |2"
    while ((getline line < decoy) > 0) print line
    close(decoy)
    next
  }
  { print }
' "$work/ci.bak" > "$work/decoy-top.yml"
awk '
  /^  (release|rust-macos|ios|macos-app|release-audit|verify-macos-binary|verify-ios-ipa|verify-macos-app|artifact-integrity):$/ {
    print
    print "    # this real job differs from the reviewed block"
    next
  }
  { print }
' "$work/decoy-top.yml" > "$ci_file"
expect_yaml_valid "$ci_file" "the top-level block scalar decoy fixture"
audit_status
expect_status 1 "$status" "a top-level block scalar must not supply a reviewed job block"
expect_text "unsafe top-level block scalar" "the audit must reject a top-level block scalar"
expect_text "release job differs from the reviewed policy block" \
  "the audit must compare the real release job, not the decoy"

# A duplicate job header is ambiguous even when its spelling differs only by
# case. Reject it instead of letting the first raw header decide the policy.
yaml_check=0
awk '1; /^  verify-ios-ipa:$/ { print "  VERIFY-IOS-IPA:" }' \
  "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a case-variant duplicate job header must fail"
expect_text "duplicate job header" "the audit must name the duplicate job header"

# An upper-case policy key is ambiguous if GitHub reads keys without case.
# A step action that the scan does not recognize must fail instead of pass.
awk '!done && /^      - uses: actions\/checkout@[0-9a-f]+ # v4/ {
  sub(/- uses:/, "- Uses:")
  done = 1
} { print }' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the upper-case uses key fixture"
audit_status
expect_status 1 "$status" "an upper-case uses key must not bypass the action allowlist"
expect_text "ambiguous case variant" "the audit must reject a case-variant policy key"
yaml_check=1

# A restored cache can carry compiled output into a tag build. Every cache
# step needs the tag guard. rust-linux is not covered by an exact block, so
# this fixture proves the scan enforces the guard on every job.
awk '
  /^  rust-linux:$/ { injob = 1; print; next }
  injob && /^        if: github.ref_type != / { injob = 0; next }
  injob && /^  [A-Za-z0-9_-]+:$/ { injob = 0 }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the cache guard fixture"
audit_status
expect_status 1 "$status" "a cache step without the tag guard must fail"
expect_text "lacks the tag guard" "the audit must require the tag guard on every cache step"

# The Rust Linux job must build the real demo engine and pass its absolute
# path to the Node contract test. Without the variable that test skips.
awk '!/^          HOTSPOTSHADE_BIN: /' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the real-engine contract fixture"
audit_status
expect_status 1 "$status" "the Node contract test must not lose its engine path"
expect_text "rust-linux differs from the reviewed policy block" \
  "the audit must compare the Rust Linux contract wiring"

# The macOS build job must keep the source snapshot fixture suite.
awk '!/^      - name: Test the source snapshot helper$/' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the macOS source snapshot fixture"
audit_status
expect_status 1 "$status" "the macOS source snapshot step must not disappear"
expect_text "rust-macos differs from the reviewed policy block" \
  "the audit must compare the macOS source snapshot step"

# A setup action can restore a dependency cache through its own `cache`
# input. That restore has no tag guard, so it must fail in a job that no exact
# block covers. The key order inside the step must not matter.
awk '1; /^          distribution: temurin$/ { print "          cache: gradle" }' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the setup-java cache fixture"
audit_status
expect_status 1 "$status" "a setup action cache input must fail"
expect_text "dependency cache without the tag guard" \
  "the audit must reject a setup action cache input"

awk '
  /^  desktop-demo:$/ { injob = 1 }
  injob && /^      - uses: actions\/setup-node@/ {
    print "      - with:"
    print "          cache: npm"
    print "          node-version: " sprintf("%c", 39) "22" sprintf("%c", 39)
    sub(/^      - /, "        ")
    print
    getline; getline
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the reordered setup-node cache fixture"
audit_status
expect_status 1 "$status" "a cache input before the action reference must fail"
expect_text "dependency cache without the tag guard" \
  "the audit must read a cache input in either key order"

{
  cat "$work/ci.bak"
  printf '  zz-cache-input:\n'
  printf '    runs-on: ubuntu-latest\n'
  printf '    steps:\n'
  printf '      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2\n'
  printf "        if: github.ref_type != 'tag'\n"
  printf '        with:\n'
  printf '          workspaces: rust\n'
  printf '          cache-on-failure: true\n'
} > "$ci_file"
expect_yaml_valid "$ci_file" "the guarded rust-cache input fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "a tag-guarded rust-cache input must still pass"

# The release environment gates the write token. Only the release job may
# name it. A second job that names it would run outside the reviewed block.
awk '1; /^    name: Lint$/ { print "    environment: release" }' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the second environment fixture"
audit_status
expect_status 1 "$status" "a second job with the release environment must fail"
expect_text "only the release job may use the release environment" \
  "the audit must reject the release environment outside the release job"

awk '1; /^    name: Android demo tests and build$/ { print "    environment:"; print "      name: release" }' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the environment mapping fixture"
audit_status
expect_status 1 "$status" "an environment mapping in another job must fail"
expect_text "only the release job may use the release environment" \
  "the audit must reject an environment mapping"

# GitHub passes an input name to the action without case, so `Cache:` is the
# cache input too. The package manager cache input of setup-node must fail.
awk '1; /^          distribution: temurin$/ { print "          Cache: gradle" }' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the upper-case cache input fixture"
audit_status
expect_status 1 "$status" "an upper-case cache input must fail"
expect_text "dependency cache without the tag guard" \
  "the audit must read a cache input without case"

awk '
  /^  desktop-demo:$/ { injob = 1 }
  injob && /^          node-version: / { print "          package-manager-cache: true"; injob = 0 }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the package manager cache fixture"
audit_status
expect_status 1 "$status" "a package manager cache input must fail"
expect_text "dependency cache without the tag guard" \
  "the audit must reject the package manager cache input"

# The tag guard must sit in the cache step mapping. A guard at the job level
# or at column zero is valid YAML but leaves the step unguarded.
for guard_indent in '' '    '; do
  {
    cat "$work/ci.bak"
    printf '  zz-cache:\n'
    printf '    runs-on: ubuntu-latest\n'
    printf '    steps:\n'
    printf '      - with:\n'
    printf '          workspaces: rust\n'
    printf '        uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2\n'
    printf "%sif: github.ref_type != 'tag'\n" "$guard_indent"
  } > "$ci_file"
  expect_yaml_valid "$ci_file" "the misplaced tag guard fixture"
  audit_status
  expect_status 1 "$status" "a tag guard outside the cache step must fail"
  expect_text "a cache step lacks the tag guard" \
    "the audit must require the guard at the step indentation"
done

# The same cache step with the guard in its own mapping passes this check.
{
  cat "$work/ci.bak"
  printf '  zz-cache:\n'
  printf '    runs-on: ubuntu-latest\n'
  printf '    steps:\n'
  printf '      - with:\n'
  printf '          workspaces: rust\n'
  printf '        uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2\n'
  printf "        if: github.ref_type != 'tag'\n"
} > "$ci_file"
expect_yaml_valid "$ci_file" "the step-level tag guard fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "a tag guard in the cache step mapping must pass"

# A condition can skip a test step or a job in a job that no exact block
# covers and leave it green. Only the reviewed guards may appear.
awk '
  /^  rust-windows:$/ { injob = 1 }
  injob && /^      - name: Test$/ { print; print "        if: false"; injob = 0; next }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the skipped test step fixture"
audit_status
expect_status 1 "$status" "a step condition in an unpinned job must fail"
expect_text "a condition can skip a step or job" \
  "the audit must reject a step condition outside the reviewed guards"

awk '1; /^  android-demo:$/ { print "    if: false" }' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the skipped job fixture"
audit_status
expect_status 1 "$status" "a job condition outside the release job must fail"
expect_text "a condition can skip a step or job" \
  "the audit must reject a job condition outside the release job"

# An unknown top-level key is not structure the audit can review.
{ cat "$work/ci.bak"; printf 'extra: value\n'; } > "$ci_file"
expect_yaml_valid "$ci_file" "the unknown top-level key fixture"
audit_status
expect_status 1 "$status" "an unknown top-level key must fail"
expect_text "unsupported top-level key" "the audit must name the unknown top-level key"

# YAML reads NEL, LS, and PS as line breaks. A two-space comment line that
# holds one would hide a real release step from an LF-only scanner. Each
# fixture adds a step to the release job that Psych reads.
for separator in '\302\205' '\342\200\250' '\342\200\251'; do
  {
    cat "$work/ci.bak"
    printf "  #$separator      - name: Extra publish step$separator        run: echo injected\n"
  } > "$ci_file"
  if [ "$ruby_yaml" -eq 1 ]; then
    steps=$(ruby -ryaml -e 'puts YAML.load_file(ARGV[0])["jobs"]["release"]["steps"].map { |s| s["name"] }.compact.last' -- "$ci_file" 2>/dev/null || true)
    [ "$steps" = "Extra publish step" ] ||
      fail "the Unicode line break fixture must add a release step that Psych reads"
  fi
  audit_status
  expect_status 1 "$status" "a Unicode line break must fail the audit"
  expect_text "unsupported byte outside printable ASCII" \
    "the audit must reject a Unicode line break"
  graph_status
  expect_status 1 "$status" "a Unicode line break must fail the graph check"
  expect_text "unsupported byte outside printable ASCII" \
    "the graph check must reject a Unicode line break"
done

# Some awk implementations end a record at a NUL byte. YAML readers reject
# NUL, but the scanners must not pass a file they cannot read whole.
yaml_check=0
{
  cat "$work/ci.bak"
  printf '  #\000      - name: Extra publish step\000        run: echo injected\n'
} > "$ci_file"
audit_status
expect_status 1 "$status" "a NUL byte must fail the audit"
expect_text "unsupported NUL byte" "the audit must reject a NUL byte"
graph_status
expect_status 1 "$status" "a NUL byte must fail the graph check"
expect_text "unsupported NUL byte" "the graph check must reject a NUL byte"
yaml_check=1

# A lone dash starts a step whose mapping begins on the next line. The cache
# input of the setup-node step before it must not carry over to the guarded
# rust-cache step that follows.
awk '
  /^  desktop-demo:$/ { injob = 1 }
  injob && /^          node-version: / { print "          cache: npm" }
  injob && /^      - uses: Swatinem\/rust-cache@/ {
    print "      -"
    sub(/^      - /, "        ")
    print
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the lone dash cache fixture"
audit_status
expect_status 1 "$status" "a cache input before a lone dash step must fail"
expect_text "dependency cache without the tag guard" \
  "the audit must end a step at a lone dash"

# The same lone dash spelling on a guarded rust-cache step passes.
{
  cat "$work/ci.bak"
  printf '  zz-lone:\n'
  printf '    runs-on: ubuntu-latest\n'
  printf '    steps:\n'
  printf '      -\n'
  printf '        uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2\n'
  printf "        if: github.ref_type != 'tag'\n"
  printf '        with:\n'
  printf '          workspaces: rust\n'
} > "$ci_file"
expect_yaml_valid "$ci_file" "the lone dash rust-cache fixture"
audit_status --require-aligned-versions
expect_status 0 "$status" "a guarded rust-cache step after a lone dash must pass"

# A `uses` key and a guard nested in `with:` are inputs, not step keys. They
# must not make a setup action look like the guarded rust-cache step.
awk -v sq="'" '
  /^  desktop-demo:$/ { injob = 1 }
  injob && /^          node-version: / {
    print "          uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2"
    print "          if: github.ref_type != " sq "tag" sq
    print "          cache: npm"
    injob = 0
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the nested uses and guard fixture"
audit_status
expect_status 1 "$status" "a uses key and guard nested in with must fail"
expect_text "action reference outside a step mapping" \
  "the audit must reject a nested uses key"
expect_text "dependency cache without the tag guard" \
  "the audit must not accept a nested guard for a setup action cache"

# A shell override or a job-level defaults, container, or services key can
# replace every command of a job and leave it green.
awk '/^      - name: Test Rust bridge and assets$/ { print; print "        shell: sh"; next } { print }' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the shell override fixture"
audit_status
expect_status 1 "$status" "a shell other than bash must fail"
expect_text "a shell other than bash" "the audit must reject a shell override"

for job_key in 'container: ubuntu:24.04' 'services:' 'defaults:'; do
  awk -v add="$job_key" '
    { print }
    /^    name: Shared desktop demo checks$/ {
      print "    " add
      if (add == "services:") { print "      cache:"; print "        image: redis:7" }
      if (add == "defaults:") { print "      run:"; print "        shell: bash" }
    }
  ' "$work/ci.bak" > "$ci_file"
  expect_yaml_valid "$ci_file" "the job-level $job_key fixture"
  audit_status
  expect_status 1 "$status" "a job-level $job_key key must fail"
  expect_text "can replace or wrap every step" \
    "the audit must reject a job-level $job_key key"
done

cp "$work/ci.bak" "$ci_file"

# ---------------------------------------------------------------------------
# Release security: action allowlist, upload ownership, and digest binding
# ---------------------------------------------------------------------------
#
# Every fixture below is valid YAML and gives GitHub a real action reference,
# upload target, or job output. A text scanner must reject it, and the exact
# block match must reject a build command or digest wiring that changed.

# A full SHA from an unreviewed action repository is still unreviewed.
awk '!done && /actions\/checkout@[0-9a-f]+ # v4/ {
  sub(/actions\/checkout@[0-9a-f]+/, "actions/checkout@1111111111111111111111111111111111111111")
  done = 1
} { print }' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the unreviewed action SHA fixture"
audit_status
expect_status 1 "$status" "an action SHA outside the reviewed allowlist must fail"
expect_text "not in the reviewed allowlist" "the audit must name the action allowlist"

# A fork can keep the repository name and a fixed SHA. The owner matters.
awk '!done && /actions\/checkout@[0-9a-f]+ # v4/ {
  sub(/actions\/checkout@/, "example-fork/checkout@")
  done = 1
} { print }' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the forked action owner fixture"
audit_status
expect_status 1 "$status" "an action from an unreviewed owner must fail"
expect_text "not in the reviewed allowlist" "the audit must compare the owner and repository"

# A job-level uses key is a reusable workflow, not a reviewed step list.
awk '/^  release:$/ {
  print "  # ci-stage: test"
  print "  reused:"
  print "    uses: octo/example/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567"
} { print }' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the reusable workflow fixture"
audit_status
expect_status 1 "$status" "a job-level reusable workflow must fail"
expect_text "job-level reusable workflow is not allowed" "the audit must reject a reusable workflow"

awk '/^  release:$/ {
  print "  # ci-stage: test"
  print "  reused:"
  print "    \"uses\": octo/example/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567"
} { print }' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the quoted reusable workflow fixture"
audit_status
expect_status 1 "$status" "a quoted job-level reusable workflow must fail"
expect_text "job-level reusable workflow is not allowed" "the audit must read a quoted reusable workflow key"

# An upload can replace verified bytes only when overwrite is on. Reject the
# key, and prove that a with mapping before uses cannot hide it.
awk '{ print } /^          path: release\/\*$/ { print "          overwrite: true" }' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the overwrite upload fixture"
audit_status
expect_status 1 "$status" "an artifact overwrite flag must fail"
expect_text "may overwrite an existing artifact" "the audit must reject overwrite"

awk '
  /^  rust-windows:$/ {
    print
    print "    runs-on: windows-latest"
    print "    timeout-minutes: 30"
    print "    steps:"
    print "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4"
    print "      - with:"
    print "          name: release-bundle"
    print "          overwrite: true"
    print "        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4"
    print "        with:"
    print "          name: release-bundle"
    print "          path: rust/target/release/hotspotshade"
    print "          retention-days: 14"
    inblock = 1
    next
  }
  inblock && /^  [a-zA-Z0-9_-]+:$/ { inblock = 0 }
  inblock { next }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the with-before-uses upload fixture"
audit_status
expect_status 1 "$status" "a with-before-uses upload must fail"
expect_text "may overwrite an existing artifact" "the audit must read an overwrite key before uses"
expect_text "may be uploaded only by job artifact-integrity" "the audit must reject a foreign release-bundle upload"

# A test job may not upload a release artifact name.
awk '
  /^  rust-windows:$/ { print; injob = 1; next }
  injob && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
    print
    print "      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4"
    print "        with:"
    print "          name: release-bundle"
    print "          path: rust/target/release/hotspotshade"
    print "          retention-days: 14"
    next
  }
  injob && /^  [a-zA-Z0-9_-]+:$/ { injob = 0 }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the foreign release-bundle fixture"
audit_status
expect_status 1 "$status" "a non-integrity job must not upload release-bundle"
expect_text "may be uploaded only by job artifact-integrity" "the audit must name the approved owner"

awk '
  /^  rust-windows:$/ { print; injob = 1; next }
  injob && /^      - uses: actions\/checkout@[0-9a-f]+ # v4$/ {
    print
    print "      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4"
    print "        with:"
    print "          name: release-bundle-extra"
    print "          path: rust/target/release/hotspotshade"
    print "          retention-days: 14"
    next
  }
  injob && /^  [a-zA-Z0-9_-]+:$/ { injob = 0 }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the unknown artifact name fixture"
audit_status
expect_status 1 "$status" "an artifact name outside the allowlist must fail"
expect_text "not in the reviewed upload allowlist" "the audit must name the upload allowlist"

# A build environment can replace the compiler driver or the loader.
awk '
  /^  rust-macos:$/ {
    print
    print "    env:"
    print "      RUSTC_WRAPPER: /bin/true"
    next
  }
  { print }
' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the RUSTC_WRAPPER fixture"
audit_status
expect_status 1 "$status" "a RUSTC_WRAPPER environment entry must fail"
expect_text "may replace a command" "the audit must reject a compiler wrapper"
expect_text "differs from the reviewed policy block" "the build block must reject an added environment"

# A build command that changes still matches no reviewed block.
sed 's#^        run: cargo build --release --locked$#        run: cargo build --release --locked \&\& true#' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the changed build command fixture"
audit_status
expect_status 1 "$status" "a changed build command must fail"
expect_text "rust-macos differs from the reviewed policy block" "the audit must reject a changed build command"

# The verifier must publish the digest of the bytes it audited.
sed 's#sha256: \${{ steps.digest.outputs.sha256 }}#sha256: ${{ github.run_id }}#' \
  "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the changed verifier digest fixture"
audit_status
expect_status 1 "$status" "a verifier output that is not the artifact digest must fail"
expect_text "differs from the reviewed policy block" "the audit must reject altered digest wiring"

# The release job must consume the integrity job's manifest output.
awk '{
  if ($0 == "          MANIFEST_SHA256: ${{ needs.artifact-integrity.outputs.manifest-sha256 }}") {
    print "          MANIFEST_SHA256: ${{ needs.artifact-integrity.outputs.sha256 }}"
    next
  }
  print
}' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the wrong manifest output fixture"
audit_status
expect_status 1 "$status" "a release job with the wrong manifest output must fail"
expect_text "differs from the reviewed policy block" "the audit must bind the manifest output"

# The release digest check is an ordered executable step, not a comment.
awk '{
  if ($0 == "          sh scripts/release_manifest.sh --expect \"$MANIFEST_SHA256\" release/SHA256SUMS") next
  print
}' "$work/ci.bak" > "$ci_file"
expect_yaml_valid "$ci_file" "the removed release digest check fixture"
audit_status
expect_status 1 "$status" "a release job without the manifest digest check must fail"
expect_text "release commands must be unconditional" "the audit must reject a removed digest step"

cp "$work/ci.bak" "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "the release security fixtures must restore cleanly"

# A second workflow file is not covered by this policy.
cat > "$tree/.github/workflows/extra.yml" <<'EOF'
name: Extra
on: [push]
jobs:
  extra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
EOF
audit_status
expect_status 1 "$status" "an additional workflow file must fail the audit"
expect_text "unreviewed workflow file" "the audit must name the unreviewed workflow"
rm -f "$tree/.github/workflows/extra.yml"

# The lint job and the test jobs are pinned, so a deleted test cannot leave a
# green job with no test command.
sed 's#^        run: cargo fmt --check$#        run: echo skipped#' \
  "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a changed lint command must fail the audit"
expect_text "lint differs from the reviewed policy block" \
  "the audit must compare the pinned lint job"

awk '!/^        run: \.\/gradlew --no-daemon testDebugUnitTest lintDebug assembleDebug assembleDebugAndroidTest$/' \
  "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a deleted Android test command must fail the audit"
expect_text "android-demo differs from the reviewed policy block" \
  "the audit must compare the pinned Android test job"

awk '
  /^  rust-windows:$/ { injob = 1; print; next }
  injob && !done && /^        run: cargo test --locked$/ { done = 1; next }
  injob && /^  [A-Za-z0-9_-]+:$/ { injob = 0 }
  { print }
' "$work/ci.bak" > "$ci_file"
audit_status
expect_status 1 "$status" "a deleted Rust Windows test command must fail the audit"
expect_text "rust-windows differs from the reviewed policy block" \
  "the audit must compare the pinned Rust Windows test job"

cp "$work/ci.bak" "$ci_file"
audit_status --require-aligned-versions
expect_status 0 "$status" "the restored workflow must pass after the spelling tests"
yaml_check=0

# ---------------------------------------------------------------------------
# CI graph
# ---------------------------------------------------------------------------

out=$(sh "$tree/scripts/ci_graph_check.sh" --workflow "$tree/.github/workflows/ci.yml" 2>&1) || {
  fail "the repository graph must pass"
  printf '%s\n' "$out" | sed 's/^/    /' >&2
}

awk '1; /^  lint:$/ { print "    needs: [release]" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "a cycle must fail the graph check"
expect_text "cycle" "the graph check must name the cycle"

awk '1; /^  rust-windows:$/ { print "    needs: [no-such-job]" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "an edge to an unknown job must fail"
expect_text "names no job" "the graph check must name the unknown job"

sed '/^    needs: \[rust-macos\]$/d' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "artifact verification must wait for its build"
expect_text "missing prerequisite edge" "the graph check must name the missing build edge"

sed '/^    needs: \[verify-macos-binary, verify-ios-ipa, verify-macos-app\]$/c\
    needs: [verify-macos-binary, verify-ios-ipa]' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "integrity must wait for all artifact verification jobs"
expect_text "missing prerequisite edge" "the graph check must name the missing verify edge"

sed "s/if: startsWith(github.ref, 'refs\/tags\/v')/if: always() \&\& startsWith(github.ref, 'refs\/tags\/v')/" \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "release must not override failed prerequisite status"
expect_text "overrides prerequisite status gating" "the graph check must reject a status override"
audit_status
expect_status 1 "$status" "the release audit must reject a status override"

sed 's#release/HotspotShade-iOS-unsigned.ipa#dist/*#' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "release must not publish an unverified asset list"
expect_text "publish exactly the audited artifact set" "the audit must identify an altered asset list"

awk '{ if (index($0, "run: sh scripts/release_audit.sh --artifacts release --tag")) sub(/ --tag.*/, ""); print }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "release must not omit the tag and strict audit options"
expect_text "strict tagged release audit" "the audit must identify the missing release gate"

awk '1; /^      - name: Audit the downloaded IPA$/ { print "        if: false" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "an artifact verification step must not be skipped"
expect_text "must not conditionally skip" "the audit must identify the skipped check"

awk '/^      - name: Audit the downloaded IPA$/ { print "      - if: false"; print "        name: Audit the downloaded IPA"; next } 1' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a first-key step condition must not skip verification"

awk '1; /^      - name: Create release$/ { print "        if: always()" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "the release step must not override a failed audit"

awk '1; /^      - name: Audit the release set against the tag$/ { print "        if: false" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "the release audit step must not be skipped"

awk '/^      - name: Audit the release set against the tag$/ { print "      - run: gh release create early" } 1' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a publish before verification must fail"

awk '/^      - name: Audit the release set against the tag$/ { print "      - \"run\": gh release create early" } 1' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "a quoted run key before verification must fail"

awk '1; /^            release\/PROVENANCE.txt$/ { print "          gh release upload extra file" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
audit_status
expect_status 1 "$status" "an additional release upload must fail"

awk '1; /^  verify-macos-binary:$/ { print "    if: success() || true" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "artifact verification must not override its build result"
expect_text "could override prerequisite status gating" "the graph check must reject a dependent job condition"

awk '1; /^  verify-ios-ipa:$/ { print "    if : always()" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "a spaced job condition must not bypass the graph check"

awk '1; /^  verify-ios-ipa:$/ { print "    \"if\": always()" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "a quoted job condition must not bypass the graph check"

awk '1; /^jobs:$/ { print "  sneaky: # alternate header"; print "    runs-on: ubuntu-latest" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "an unrecognized job header must not disappear from the graph"
expect_text "unsupported job header" "the graph check must identify unsupported syntax"

# A case-variant duplicate job header is ambiguous: GitHub and the graph
# check could read different jobs. The graph check must reject it.
awk '1; /^  verify-ios-ipa:$/ { print "  VERIFY-IOS-IPA:" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "a case-variant duplicate job header must fail the graph check"
expect_text "duplicate job header" "the graph check must name the duplicate job header"

# An upper-case needs key is ambiguous if GitHub reads keys without case.
# The graph check must not silently lose the edge.
awk '!done && /^    needs: \[rust-macos\]$/ {
  sub(/needs:/, "NEEDS:")
  done = 1
} { print }' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "an upper-case needs key must fail the graph check"
expect_text "ambiguous case variant" "the graph check must reject a case-variant needs key"

# A top-level block scalar can hold a line that looks like a job header. The
# graph check reads only the one plain jobs mapping.
awk 'NR == 1 { print "name: |2"; print "  release:"; print "    needs: []"; next } { print }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "a top-level block scalar must fail the graph check"
expect_text "unsafe top-level block scalar" "the graph check must reject a top-level block scalar"

# An indented comment after a top-level scalar is valid YAML and continues
# nothing. The graph check must accept it, as the audit does.
awk 'NR == 1 { print; print "  # an indented comment"; next } { print }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the indented comment fixture"
graph_status
expect_status 0 "$status" "an indented comment after a top-level scalar must pass the graph check"

# A merge key can move a condition into a job without a line the graph check
# reads as a condition. The graph check must reject the spelling by itself.
awk '{ print } /^  verify-macos-binary:$/ { print "    <<: &skip"; print "      if: always()" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the graph merge key fixture"
graph_status
expect_status 1 "$status" "a merge key must fail the graph check"
expect_text "unsupported YAML merge key, anchor, alias, or tag" \
  "the graph check must reject a merge key"

grep -v '^  # ci-stage: integration$' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "a job without a stage tag must fail"
expect_text "no \"# ci-stage:\" tag" "the graph check must name the untagged job"

# A duplicate needs key can hide the edge that GitHub reads. Psych keeps the
# second value, so the graph check must reject the duplicate spelling.
awk '1; /^    needs: \[rust-macos\]$/ { print "    needs: []" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the duplicate needs fixture"
expect_yaml_needs_json "$tree/.github/workflows/ci.yml" verify-macos-binary "[]" \
  "the duplicate needs fixture"
graph_status
expect_status 1 "$status" "a duplicate needs key must fail the graph check"
expect_text "duplicate key needs in job verify-macos-binary" \
  "the graph check must name the duplicate needs key"

# A duplicate steps key is ambiguous for the graph as well.
awk '1; /^  verify-macos-binary:$/ { print "    steps: []" }' \
  "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the duplicate steps graph fixture"
graph_status
expect_status 1 "$status" "a duplicate steps key must fail the graph check"
expect_text "duplicate key steps in job verify-macos-binary" \
  "the graph check must name the duplicate steps key"

# A flow sequence that closes on the next line can carry an edge the graph
# check does not read. Reject the multi-line spelling.
awk '
  /^  verify-macos-binary:$/ { print; injob = 1; next }
  injob && /^    needs: \[rust-macos\]$/ {
    print "    needs: [rust-macos,"
    print "      artifact-integrity]"
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the multi-line needs fixture"
graph_status
expect_status 1 "$status" "a multi-line flow needs list must fail the graph check"
expect_text "unsupported multi-line flow sequence" \
  "the graph check must reject a multi-line flow needs list"

# A block sequence may sit at the same indentation as its `needs:` key. That
# is valid YAML, and GitHub reads the same edges as the indented spelling. The
# graph check and the audit prerequisite check must both read them.
awk '
  /^  release:$/ { inrel = 1; inneed = 0; print; next }
  inrel && /^  [A-Za-z0-9_-]+:$/ { inrel = 0; inneed = 0 }
  inrel && /^    needs:$/ { inneed = 1; print; next }
  inrel && inneed && /^      - / { sub(/^      /, "    "); print; next }
  inrel && inneed && /^    [^ ]/ { inneed = 0 }
  { print }
' "$work/ci.bak" > "$work/ci-same-indent.yml"
expect_yaml_valid "$work/ci-same-indent.yml" "the same-indent needs fixture"
cp "$work/ci-same-indent.yml" "$tree/.github/workflows/ci.yml"
graph_status
expect_status 0 "$status" "a same-indent needs sequence must pass the graph check"
expect_text "artifact-integrity" "the graph check must read a same-indent needs entry"
audit_status --require-aligned-versions
expect_status 1 "$status" "the audit still rejects the changed reviewed release block"
expect_no_text "does not wait for" \
  "the audit prerequisite check must read a same-indent needs sequence"

grep -v '^    - artifact-integrity$' "$work/ci-same-indent.yml" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "a same-indent needs list that misses an edge must fail"
expect_text "does not wait for" \
  "the graph check must notice a missing same-indent prerequisite"

# An indentation that is neither the key column nor one level deeper is not a
# reviewed spelling. Reject it instead of silently dropping the edge.
sed 's/^      - lint$/       - lint/' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
graph_status
expect_status 1 "$status" "an unreviewed needs indentation must fail the graph check"
expect_text "unsupported needs sequence indentation" \
  "the graph check must reject an unreviewed needs indentation"

# A plain scalar can continue on a more indented line and hide part of a job
# value from the graph check.
awk '
  /^  rust-windows:$/ { print; injob = 1; next }
  injob && /^    runs-on: windows-latest$/ {
    print
    print "      extra"
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the graph plain scalar fixture"
graph_status
expect_status 1 "$status" "a plain scalar continuation must fail the graph check"
expect_text "unsupported plain scalar continuation" \
  "the graph check must reject a plain scalar continuation"

# The same continuation within a needs list can change the edge name.
awk '
  /^  release:$/ { print; injob = 1; next }
  injob && /^      - lint$/ {
    print
    print "        extra"
    injob = 0
    next
  }
  { print }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the graph needs continuation fixture"
graph_status
expect_status 1 "$status" "a needs list continuation must fail the graph check"
expect_text "unsupported plain scalar continuation" \
  "the graph check must reject a needs list continuation"

# Stage tags are pinned to job IDs. Swapping them must fail rather than let a
# job claim another evidence class.
awk '
  {
    if ($0 ~ /^  # ci-stage:/) { stage = $0; next }
    if ($0 ~ /^  [A-Za-z0-9_-]+:$/) {
      id = $0
      sub(/^  /, "", id)
      sub(/:$/, "", id)
      if (id == "lint" && stage != "") {
        print "  # ci-stage: test"
        stage = ""
        print
        next
      }
      if (id == "rust-windows" && stage != "") {
        print "  # ci-stage: policy"
        stage = ""
        print
        next
      }
      if (stage != "") { print stage; stage = "" }
      print
      next
    }
    if (stage != "") { print stage; stage = "" }
    print
  }
  END { if (stage != "") print stage }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the moved stage tag fixture"
graph_status
expect_status 1 "$status" "a moved stage tag must fail the graph check"
expect_text "expected pinned stage" "the graph check must pin stage mappings"

# A new job with a known stage tag is outside the pinned mapping.
awk '
  /^jobs:$/ {
    print
    print "  # ci-stage: test"
    print "  extra-job:"
    print "    runs-on: ubuntu-latest"
    print "    steps: []"
    next
  }
  { print }
' "$work/ci.bak" > "$tree/.github/workflows/ci.yml"
expect_yaml_valid "$tree/.github/workflows/ci.yml" "the unpinned job fixture"
graph_status
expect_status 1 "$status" "a job outside the pinned stage mapping must fail"
expect_text "no pinned stage mapping" "the graph check must reject an unpinned job"

cp "$work/ci.bak" "$tree/.github/workflows/ci.yml"
graph_status
expect_status 0 "$status" "the restored graph must pass"

# An unreadable workflow is not an empty graph. The check must refuse to read
# it instead of passing a file it could not open.
chmod 000 "$tree/.github/workflows/ci.yml"
if [ -r "$tree/.github/workflows/ci.yml" ]; then
  echo "note: this user can read a 000 file; the unreadable-workflow fixture is skipped" >&2
else
  graph_status
  expect_status 2 "$status" "an unreadable workflow must be a usage error"
  expect_text "Not readable:" "the graph check must name an unreadable workflow"
fi
chmod 644 "$tree/.github/workflows/ci.yml"
graph_status
expect_status 0 "$status" "the workflow fixture must restore after the unreadable check"

# ---------------------------------------------------------------------------
# Tracked-file scan: force-added build output and awkward names
# ---------------------------------------------------------------------------
#
# The older find scan pruned build directories, so a force-added build secret
# was invisible. Use the git index, and pass NUL-separated names so a space
# cannot split a path. The audit prints the path only, never the content.

if command -v git >/dev/null 2>&1; then
  git -C "$tree" init -q
  git -C "$tree" config user.email test@example.invalid
  git -C "$tree" config user.name "Release Test"
  git -C "$tree" add -A
  mkdir -p "$tree/build"
  printf 'not a real key\n' > "$tree/build/identity.key"
  printf 'not a real key\n' > "$tree/build/identity key.p12"
  printf 'not a real key\n' > "$tree/build/Key.PEM"
  printf 'note\n' > "$tree/notes.txt"
  printf 'AKIA%s\n' 'ABCDEFGHIJKLMNOP' > "$tree/build/access.txt"
  printf '\000\000AKIA%s\n' 'QRSTUVWXYZ012345' > "$tree/build/blob.bin"
  printf '%s\n' '-----BEGIN PGP PRIVATE'" KEY BLOCK-----" > "$tree/build/keyblock.txt"
  git -C "$tree" add -f "$tree/build/identity.key" "$tree/build/identity key.p12" \
    "$tree/build/Key.PEM" "$tree/build/access.txt" "$tree/build/blob.bin" \
    "$tree/build/keyblock.txt"
  git -C "$tree" add "$tree/notes.txt"
  audit_status
  expect_status 1 "$status" "a force-added build secret must fail the audit"
  expect_text "build/identity.key" "the audit must name a force-added build key"
  expect_text "build/identity key.p12" "the audit must keep a name with a space in one piece"
  expect_text "build/Key.PEM" "the audit must match a signing name without case"
  expect_text "build/access.txt" "the audit must name a token marker without printing it"
  expect_text "build/blob.bin" "the audit must read a binary file for a token marker"
  expect_text "build/keyblock.txt" "the audit must name a private key block header"

  # The access file test above must not leak the marker into the report.
  if printf '%s\n' "$out" | grep -F "AKIA$(printf 'ABCDEFGHIJKLMNOP')" >/dev/null; then
    fail "the audit printed a secret value"
  fi

  # An unreadable tracked file is not a clean file. The scan must fail closed
  # and must not print the content it could not read.
  marker="AKIA$(printf 'UNREADABLESECRET1')"
  printf '%s\n' "$marker" > "$tree/build/unreadable.txt"
  git -C "$tree" add -f "$tree/build/unreadable.txt"
  chmod 000 "$tree/build/unreadable.txt"
  if [ -r "$tree/build/unreadable.txt" ]; then
    echo "note: this user can read a 000 file; the unreadable-file fixture is skipped" >&2
  else
    audit_status
    expect_status 1 "$status" "an unreadable tracked file must fail closed"
    expect_text "tracked file is missing or unreadable: build/unreadable.txt" \
      "the audit must name an unreadable tracked file"
    if printf '%s\n' "$out" | grep -F "$marker" >/dev/null; then
      fail "the audit printed content from an unreadable tracked file"
    fi
  fi
  chmod 644 "$tree/build/unreadable.txt"
  git -C "$tree" rm --cached -q "$tree/build/unreadable.txt"
  rm -f "$tree/build/unreadable.txt"

  # A failed git ls-files must not look like an empty tree.
  cp "$tree/.git/index" "$work/index.bak"
  printf 'not a git index\n' > "$tree/.git/index"
  audit_status
  expect_status 1 "$status" "a failed git ls-files must fail closed"
  expect_text "cannot enumerate tracked files with git ls-files" \
    "the audit must report a failed git ls-files"
  cp "$work/index.bak" "$tree/.git/index"

  rm -rf "$tree/.git" "$tree/build" "$tree/notes.txt"
  audit_status --require-aligned-versions
  expect_status 0 "$status" "the tracked-file fixture must restore cleanly"

  # The find fallback must also fail closed when a directory cannot be read.
  plain=$work/plain-tree
  mkdir -p "$plain/rust" "$plain/hidden"
  cat > "$plain/rust/Cargo.toml" <<'EOF'
[package]
name = "hotspotshade"
version = "9.9.9"
EOF
  marker="AKIA$(printf 'UNREADABLESECRET2')"
  printf '%s\n' "$marker" > "$plain/hidden/secret.txt"
  chmod 000 "$plain/hidden"
  if [ -r "$plain/hidden" ]; then
    echo "note: this user can read a 000 directory; the find fixture is skipped" >&2
  else
    set +e
    out=$(sh "$tree/scripts/release_audit.sh" --repo-root "$plain" 2>&1)
    status=$?
    set -e
    expect_status 1 "$status" "a failed find must fail closed"
    expect_text "cannot enumerate the tree with find" \
      "the audit must report a failed find"
    if printf '%s\n' "$out" | grep -F "$marker" >/dev/null; then
      fail "the audit printed content from an unreadable directory"
    fi
  fi
  chmod 755 "$plain/hidden"
  rm -rf "$plain"
else
  echo "note: git is unavailable; the tracked-file scan fixture is skipped" >&2
fi

# ---------------------------------------------------------------------------
# Artifacts and the checksum manifest
# ---------------------------------------------------------------------------

if ! command -v zip >/dev/null 2>&1; then
  fail "zip is missing; the artifact tests cannot run"
else
  artifacts=$work/artifacts
  mkdir -p "$artifacts"
  mkdir -p "$work/ipa/Payload/HotspotProxy.app"
  cat > "$work/ipa/Payload/HotspotProxy.app/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<string>9.9.9</string>
</dict>
</plist>
PLIST
  write_test_macho "$work/ipa/Payload/HotspotProxy.app/HotspotProxy" 2
  chmod 755 "$work/ipa/Payload/HotspotProxy.app/HotspotProxy"
  (cd "$work/ipa" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
  mkdir -p "$work/app/HotspotShade.app/Contents/_CodeSignature"
  mkdir -p "$work/app/HotspotShade.app/Contents/MacOS"
  cat > "$work/app/HotspotShade.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<string>9.9.9</string>
</dict>
</plist>
PLIST
  write_test_macho "$work/app/HotspotShade.app/Contents/MacOS/HotspotShade" 1
  chmod 755 "$work/app/HotspotShade.app/Contents/MacOS/HotspotShade"
  printf 'signature\n' > "$work/app/HotspotShade.app/Contents/_CodeSignature/CodeResources"
  (cd "$work/app" && zip -qr "$artifacts/HotspotShade-unsigned.zip" HotspotShade.app)
  write_test_macho "$artifacts/hotspotshade-macos-arm64.bin"

  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null || fail "the manifest must be written"
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1) || fail "the written manifest must verify"
  expect_text "Verified 4 files" "the manifest must cover every artifact and the provenance record"

  # The job-output binding uses one digest mode for the verifier and one for
  # the consumer. A wrong or malformed expected digest must fail.
  manifest_digest=$(sh "$tree/scripts/release_manifest.sh" --digest "$artifacts/SHA256SUMS")
  if [ "${#manifest_digest}" -ne 64 ]; then
    fail "the digest mode must print one SHA-256"
  fi
  sh "$tree/scripts/release_manifest.sh" --expect "$manifest_digest" "$artifacts/SHA256SUMS" >/dev/null ||
    fail "the expect mode must accept the matching digest"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --expect \
    0000000000000000000000000000000000000000000000000000000000000000 \
    "$artifacts/SHA256SUMS" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "a wrong expected digest must fail"
  expect_text "MISMATCH" "the expect mode must name a digest mismatch"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --expect not-a-digest "$artifacts/SHA256SUMS" 2>&1)
  status=$?
  set -e
  expect_status 2 "$status" "a malformed expected digest must be a usage error"
  expect_text "64 lowercase hex" "the expect mode must explain the digest shape"

  cp "$artifacts/SHA256SUMS" "$work/sums.bak"
  sed '/  HotspotShade-unsigned\.zip$/d' "$work/sums.bak" > "$artifacts/SHA256SUMS"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "an unlisted artifact must fail verification"
  expect_text "UNLISTED  HotspotShade-unsigned.zip" "the missing entry must be named"
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "the audit must reject an unlisted artifact"
  cp "$work/sums.bak" "$artifacts/SHA256SUMS"

  head -n 1 "$work/sums.bak" >> "$artifacts/SHA256SUMS"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "a duplicate manifest entry must fail verification"
  expect_text "DUPLICATE" "the duplicate entry must be identified"
  cp "$work/sums.bak" "$artifacts/SHA256SUMS"

  printf '%064d  ../outside\n' 0 >> "$artifacts/SHA256SUMS"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "a path outside the artifact directory must fail"
  expect_text "INVALID" "the invalid entry must be identified"
  cp "$work/sums.bak" "$artifacts/SHA256SUMS"

  printf 'extra\n' > "$artifacts/.unlisted"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "an unlisted hidden artifact must fail verification"
  expect_text "UNLISTED  .unlisted" "the hidden artifact must be identified"
  rm "$artifacts/.unlisted"

  mv "$artifacts/HotspotShade-unsigned.zip" "$work/app.zip"
  ln -s "$work/app.zip" "$artifacts/HotspotShade-unsigned.zip"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "a symlinked artifact must fail verification"
  expect_text "non-regular artifact" "the symlinked artifact must be identified"
  rm "$artifacts/HotspotShade-unsigned.zip"
  mv "$work/app.zip" "$artifacts/HotspotShade-unsigned.zip"

  mv "$artifacts/SHA256SUMS" "$work/sums.real"
  ln -s "$work/sums.real" "$artifacts/SHA256SUMS"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "a symlinked manifest must fail verification"
  expect_text "No regular SHA256SUMS" "the symlinked manifest must be identified"
  rm "$artifacts/SHA256SUMS"
  mv "$work/sums.real" "$artifacts/SHA256SUMS"

  GITHUB_SHA=unknown sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts" --tag v9.9.9
  expect_status 1 "$status" "a tagged release must not accept an unknown provenance commit"
  expect_text "must name a full commit SHA" "the missing commit must be explained"

  fixture_sha=0123456789abcdef0123456789abcdef01234567
  GITHUB_SHA=$fixture_sha sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  GITHUB_SHA=$fixture_sha audit_status --artifacts "$artifacts" --tag v9.9.9
  expect_status 0 "$status" "matching full provenance must pass the tagged audit"
  GITHUB_SHA=1111111111111111111111111111111111111111 audit_status --artifacts "$artifacts" --tag v9.9.9
  expect_status 1 "$status" "a provenance commit different from the workflow commit must fail"
  expect_text "does not match the workflow commit" "the provenance mismatch must be explained"

  mv "$artifacts/HotspotShade-iOS-unsigned.ipa" "$work/missing.ipa"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts" --tag v9.9.9
  expect_status 1 "$status" "a tagged release must fail when an expected artifact is absent"
  expect_text "missing a regular file: HotspotShade-iOS-unsigned.ipa" "the missing release artifact must be named"
  mv "$work/missing.ipa" "$artifacts/HotspotShade-iOS-unsigned.ipa"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  audit_status --artifacts "$artifacts"
  expect_status 0 "$status" "an unsigned artifact set must pass the audit"
  expect_text "the binary is a Mach-O arm64 executable" "the audit must check the architecture"
  expect_text "the IPA is unsigned" "the audit must check the IPA signature"

  # The IPA must hold one app bundle at the reviewed path, not an extra app or
  # a bundle with another name.
  cp "$artifacts/HotspotShade-iOS-unsigned.ipa" "$work/safe.ipa"
  mkdir -p "$work/extraipa/Payload/Other.app"
  printf 'other\n' > "$work/extraipa/Payload/Other.app/Info.plist"
  (cd "$work/extraipa" && zip -q "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload/Other.app/Info.plist)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an extra app bundle in the IPA must fail"
  expect_text "exactly one app bundle at Payload/HotspotProxy.app" \
    "the audit must reject an extra IPA app bundle"
  cp "$work/safe.ipa" "$artifacts/HotspotShade-iOS-unsigned.ipa"

  mkdir -p "$work/wrongipa/Payload/Wrong.app"
  printf 'wrong\n' > "$work/wrongipa/Payload/Wrong.app/Info.plist"
  rm -f "$artifacts/HotspotShade-iOS-unsigned.ipa"
  (cd "$work/wrongipa" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an IPA with the wrong app bundle name must fail"
  expect_text "exactly one app bundle at Payload/HotspotProxy.app" \
    "the audit must require the intended IPA app bundle"
  cp "$work/safe.ipa" "$artifacts/HotspotShade-iOS-unsigned.ipa"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # The macOS zip must hold one HotspotShade.app, with no sibling or nested
  # app bundle.
  cp "$artifacts/HotspotShade-unsigned.zip" "$work/safe.zip"
  mkdir -p "$work/extraapp/Other.app/Contents"
  printf 'other\n' > "$work/extraapp/Other.app/Contents/Info.plist"
  (cd "$work/extraapp" && zip -q "$artifacts/HotspotShade-unsigned.zip" Other.app/Contents/Info.plist)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an extra app bundle in the macOS zip must fail"
  expect_text "exactly one app bundle at HotspotShade.app" \
    "the audit must reject an extra macOS app bundle"
  cp "$work/safe.zip" "$artifacts/HotspotShade-unsigned.zip"

  mkdir -p "$work/nestedapp/HotspotShade.app/Contents/Helpers/Extra.app"
  printf 'nested\n' > "$work/nestedapp/HotspotShade.app/Contents/Helpers/Extra.app/Info.plist"
  (cd "$work/nestedapp" && zip -q "$artifacts/HotspotShade-unsigned.zip" HotspotShade.app/Contents/Helpers/Extra.app/Info.plist)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "a nested app bundle in the macOS zip must fail"
  expect_text "exactly one app bundle at HotspotShade.app" \
    "the audit must reject a nested macOS app bundle"
  cp "$work/safe.zip" "$artifacts/HotspotShade-unsigned.zip"

  mkdir -p "$work/wrongapp/Wrong.app/Contents"
  printf 'wrong\n' > "$work/wrongapp/Wrong.app/Contents/Info.plist"
  rm -f "$artifacts/HotspotShade-unsigned.zip"
  (cd "$work/wrongapp" && zip -qr "$artifacts/HotspotShade-unsigned.zip" Wrong.app)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "a macOS zip with the wrong app name must fail"
  expect_text "exactly one app bundle at HotspotShade.app" \
    "the audit must require the intended macOS app bundle"
  cp "$work/safe.zip" "$artifacts/HotspotShade-unsigned.zip"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  printf 'outside\n' > "$work/ipa/outside"
  (cd "$work/ipa/Payload" && zip -q "$artifacts/HotspotShade-iOS-unsigned.ipa" ../outside)
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an archive with a parent path must fail"
  expect_text "archive contains an unsafe path" "the audit must identify the parent path"
  cp "$work/safe.ipa" "$artifacts/HotspotShade-iOS-unsigned.ipa"

  ln -s /etc/passwd "$work/ipa/Payload/HotspotProxy.app/link"
  (cd "$work/ipa" && zip -qy "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload/HotspotProxy.app/link)
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an archive with a symbolic link must fail"
  expect_text "archive contains a symbolic link" "the audit must identify the link"
  rm "$work/ipa/Payload/HotspotProxy.app/link"
  cp "$work/safe.ipa" "$artifacts/HotspotShade-iOS-unsigned.ipa"

  # A signed IPA must fail.
  cp "$artifacts/HotspotShade-iOS-unsigned.ipa" "$work/ipa.bak"
  mkdir -p "$work/signed/Payload/HotspotProxy.app/_CodeSignature"
  printf 'x\n' > "$work/signed/Payload/HotspotProxy.app/_CodeSignature/CodeResources"
  rm -f "$artifacts/HotspotShade-iOS-unsigned.ipa"
  (cd "$work/signed" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "a signed IPA must fail the audit"
  expect_text "must be unsigned" "the audit must reject a signed IPA"
  cp "$work/ipa.bak" "$artifacts/HotspotShade-iOS-unsigned.ipa"

  # A key, PEM, p8, or certificate entry in the IPA is signing material even
  # when it is not a provisioning profile. The zip tool proves the entry is
  # present before the audit must reject it.
  cp "$artifacts/HotspotShade-iOS-unsigned.ipa" "$work/ipa-clean.zip"
  for entry in secret.key auth.pem AuthKey.p8 cert.crt Key.PEM; do
    mkdir -p "$work/leakipa/Payload/HotspotProxy.app"
    printf 'not a real key\n' > "$work/leakipa/Payload/HotspotProxy.app/$entry"
    (cd "$work/leakipa" && zip -q "$artifacts/HotspotShade-iOS-unsigned.ipa" \
      "Payload/HotspotProxy.app/$entry")
    unzip -Z1 "$artifacts/HotspotShade-iOS-unsigned.ipa" |
      grep -Fx "Payload/HotspotProxy.app/$entry" >/dev/null ||
      fail "the IPA fixture did not add $entry"
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts"
    expect_status 1 "$status" "an IPA with $entry must fail the archive check"
    expect_text "the IPA holds signing material" \
      "the audit must reject $entry in the IPA"
    cp "$work/ipa-clean.zip" "$artifacts/HotspotShade-iOS-unsigned.ipa"
    rm -rf "$work/leakipa"
  done
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # The app archive has the same rule.
  cp "$artifacts/HotspotShade-unsigned.zip" "$work/app-clean.zip"
  for entry in secret.key auth.pem AuthKey.p8 cert.crt Key.PEM; do
    mkdir -p "$work/leakapp/HotspotShade.app/Contents"
    printf 'not a real key\n' > "$work/leakapp/HotspotShade.app/Contents/$entry"
    (cd "$work/leakapp" && zip -q "$artifacts/HotspotShade-unsigned.zip" \
      "HotspotShade.app/Contents/$entry")
    unzip -Z1 "$artifacts/HotspotShade-unsigned.zip" |
      grep -Fx "HotspotShade.app/Contents/$entry" >/dev/null ||
      fail "the app archive fixture did not add $entry"
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts"
    expect_status 1 "$status" "an app archive with $entry must fail the audit"
    expect_text "the app archive holds signing material" \
      "the audit must reject $entry in the app archive"
    cp "$work/app-clean.zip" "$artifacts/HotspotShade-unsigned.zip"
    rm -rf "$work/leakapp"
  done
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # A listed zip is not enough. The app bundle must hold a nonempty Info.plist
  # and a nonempty executable, and the executable must carry the execute bit.
  cp "$artifacts/HotspotShade-iOS-unsigned.ipa" "$work/structure.ipa"
  make_ipa() {
    # make_ipa DEST PLIST_MODE EXEC_MODE
    rm -rf "$work/ipa-variant"
    mkdir -p "$work/ipa-variant/Payload/HotspotProxy.app"
    case "$2" in
      present)
        cat > "$work/ipa-variant/Payload/HotspotProxy.app/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<string>9.9.9</string>
</dict>
</plist>
PLIST
        ;;
      empty) : > "$work/ipa-variant/Payload/HotspotProxy.app/Info.plist" ;;
      missing) ;;
    esac
    case "$3" in
      present)
        write_test_macho "$work/ipa-variant/Payload/HotspotProxy.app/HotspotProxy" 2
        chmod 755 "$work/ipa-variant/Payload/HotspotProxy.app/HotspotProxy"
        ;;
      empty)
        : > "$work/ipa-variant/Payload/HotspotProxy.app/HotspotProxy"
        chmod 755 "$work/ipa-variant/Payload/HotspotProxy.app/HotspotProxy"
        ;;
      noexec)
        write_test_macho "$work/ipa-variant/Payload/HotspotProxy.app/HotspotProxy" 2
        chmod 644 "$work/ipa-variant/Payload/HotspotProxy.app/HotspotProxy"
        ;;
      missing) ;;
    esac
    rm -f "$1"
    (cd "$work/ipa-variant" && zip -qr "$1" Payload)
  }

  for variant in 'missing|present' 'empty|present' 'present|missing' 'present|empty' 'present|noexec'; do
    plist_mode=${variant%%|*}
    exec_mode=${variant#*|}
    make_ipa "$artifacts/HotspotShade-iOS-unsigned.ipa" "$plist_mode" "$exec_mode"
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts"
    expect_status 1 "$status" "an IPA with $plist_mode Info.plist and $exec_mode executable must fail"
    if [ "$plist_mode" != present ]; then
      expect_text "the app bundle has no nonempty Info.plist" \
        "the audit must require a nonempty IPA Info.plist"
    elif [ "$exec_mode" = noexec ]; then
      expect_text "is not marked executable" \
        "the audit must require an executable IPA binary"
    else
      expect_text "the app bundle has no nonempty executable Payload/HotspotProxy.app/HotspotProxy" \
        "the audit must require a nonempty IPA executable"
    fi
    cp "$work/structure.ipa" "$artifacts/HotspotShade-iOS-unsigned.ipa"
  done
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  cp "$artifacts/HotspotShade-unsigned.zip" "$work/structure.zip"
  make_app_zip() {
    # make_app_zip DEST PLIST_MODE EXEC_MODE
    rm -rf "$work/app-variant"
    mkdir -p "$work/app-variant/HotspotShade.app/Contents/MacOS"
    case "$2" in
      present)
        cat > "$work/app-variant/HotspotShade.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<string>9.9.9</string>
</dict>
</plist>
PLIST
        ;;
      empty) : > "$work/app-variant/HotspotShade.app/Contents/Info.plist" ;;
      missing) ;;
    esac
    case "$3" in
      present)
        write_test_macho "$work/app-variant/HotspotShade.app/Contents/MacOS/HotspotShade" 1
        chmod 755 "$work/app-variant/HotspotShade.app/Contents/MacOS/HotspotShade"
        ;;
      empty)
        : > "$work/app-variant/HotspotShade.app/Contents/MacOS/HotspotShade"
        chmod 755 "$work/app-variant/HotspotShade.app/Contents/MacOS/HotspotShade"
        ;;
      noexec)
        write_test_macho "$work/app-variant/HotspotShade.app/Contents/MacOS/HotspotShade" 1
        chmod 644 "$work/app-variant/HotspotShade.app/Contents/MacOS/HotspotShade"
        ;;
      missing) ;;
    esac
    rm -f "$1"
    (cd "$work/app-variant" && zip -qr "$1" HotspotShade.app)
  }

  for variant in 'missing|present' 'empty|present' 'present|missing' 'present|empty' 'present|noexec'; do
    plist_mode=${variant%%|*}
    exec_mode=${variant#*|}
    make_app_zip "$artifacts/HotspotShade-unsigned.zip" "$plist_mode" "$exec_mode"
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts"
    expect_status 1 "$status" "an app archive with $plist_mode Info.plist and $exec_mode executable must fail"
    if [ "$plist_mode" != present ]; then
      expect_text "the app bundle has no nonempty Info.plist" \
        "the audit must require a nonempty app Info.plist"
    elif [ "$exec_mode" = noexec ]; then
      expect_text "is not marked executable" \
        "the audit must require an executable app binary"
    else
      expect_text "the app bundle has no nonempty executable HotspotShade.app/Contents/MacOS/HotspotShade" \
        "the audit must require a nonempty app executable"
    fi
    cp "$work/structure.zip" "$artifacts/HotspotShade-unsigned.zip"
  done
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # The IPA executable must be an iOS binary and the macOS app executable a
  # macOS binary. A valid Mach-O for the other platform must not pass, so the
  # two artifact checks cannot share one permissive platform rule.
  rm -rf "$work/ipa-platform"
  mkdir -p "$work/ipa-platform/Payload/HotspotProxy.app"
  cp "$work/ipa/Payload/HotspotProxy.app/Info.plist" \
    "$work/ipa-platform/Payload/HotspotProxy.app/Info.plist"
  write_test_macho "$work/ipa-platform/Payload/HotspotProxy.app/HotspotProxy" 1
  chmod 755 "$work/ipa-platform/Payload/HotspotProxy.app/HotspotProxy"
  (cd "$work/ipa-platform" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "a macOS executable in the IPA must fail the audit"
  expect_text "does not declare the expected ios platform" \
    "the audit must require the iOS platform in the IPA executable"
  cp "$work/structure.ipa" "$artifacts/HotspotShade-iOS-unsigned.ipa"

  rm -rf "$work/app-platform"
  mkdir -p "$work/app-platform/HotspotShade.app/Contents/MacOS"
  cp "$work/app/HotspotShade.app/Contents/Info.plist" \
    "$work/app-platform/HotspotShade.app/Contents/Info.plist"
  write_test_macho "$work/app-platform/HotspotShade.app/Contents/MacOS/HotspotShade" 2
  chmod 755 "$work/app-platform/HotspotShade.app/Contents/MacOS/HotspotShade"
  (cd "$work/app-platform" && zip -qr "$artifacts/HotspotShade-unsigned.zip" HotspotShade.app)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an iOS executable in the macOS app must fail the audit"
  expect_text "does not declare the expected macos platform" \
    "the audit must require the macOS platform in the app executable"
  cp "$work/structure.zip" "$artifacts/HotspotShade-unsigned.zip"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # A ZIP whose directory lists but whose entry data fails a CRC must fail.
  corrupt_zip() {
    # corrupt_zip SOURCE DEST
    off=100
    while [ "$off" -le 800 ]; do
      cp "$1" "$2"
      printf '\377' | dd of="$2" bs=1 seek="$off" conv=notrunc 2>/dev/null
      if ! unzip -t "$2" >/dev/null 2>&1 && unzip -Z1 "$2" >/dev/null 2>&1; then
        return 0
      fi
      off=$((off + 1))
    done
    return 1
  }
  if corrupt_zip "$work/structure.zip" "$artifacts/HotspotShade-unsigned.zip"; then
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts"
    expect_status 1 "$status" "a corrupted ZIP must fail the audit"
    expect_text "the archive is corrupt or cannot be read" \
      "the audit must reject a ZIP that fails its integrity test"
    cp "$work/structure.zip" "$artifacts/HotspotShade-unsigned.zip"
  else
    fail "the corrupted ZIP fixture could not be built"
  fi
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # The entry point must be inside a nonempty executable segment, not at EOF
  # and not in a read-only or zero-size segment.
  patch_bytes() {
    # patch_bytes FILE OFFSET ESCAPED_BYTES
    printf '%b' "$3" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
  }
  write_test_macho "$work/macho-valid"
  for patch in '112|\000\020\000\000\000\000\000\000|EOF entry' '92|\001\000\000\000|non-executable segment' '80|\000\000\000\000\000\000\000\000|zero-size segment'; do
    offset=${patch%%|*}
    rest=${patch#*|}
    bytes=${rest%%|*}
    label=${rest#*|}
    cp "$work/macho-valid" "$artifacts/hotspotshade-macos-arm64.bin"
    patch_bytes "$artifacts/hotspotshade-macos-arm64.bin" "$offset" "$bytes"
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts"
    expect_status 1 "$status" "a Mach-O with an $label must fail the audit"
    expect_text "the binary entry point is not inside a nonempty executable segment" \
      "the audit must reject a Mach-O entry outside an executable segment ($label)"
  done
  cp "$work/macho-valid" "$artifacts/hotspotshade-macos-arm64.bin"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # An entry point inside the header or load commands is a stub, not a
  # runnable image.
  cp "$work/macho-valid" "$artifacts/hotspotshade-macos-arm64.bin"
  patch_bytes "$artifacts/hotspotshade-macos-arm64.bin" 112 '\000\000\000\000'
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "a Mach-O stub entry point must fail the audit"
  expect_text "entry point overlaps the header or load commands" \
    "the audit must reject an entry point in the header area"

  # A load-command area with repeated 16-byte rows must not be collapsed by
  # od. Without od -v, a repeated row prints as * and the command length check
  # rejects a valid file.
  write_test_macho "$work/macho-repeat" 1 1
  if command -v file >/dev/null 2>&1; then
    file_output=$(file "$work/macho-repeat")
    case "$file_output" in
      *Mach-O*arm64*) ;;
      *) fail "the repeated-row Mach-O fixture is not recognized as an arm64 Mach-O ($file_output)" ;;
    esac
  fi
  if command -v otool >/dev/null 2>&1; then
    otool -l "$work/macho-repeat" >/dev/null 2>&1 ||
      fail "the repeated-row Mach-O fixture does not parse with otool"
  fi
  cp "$work/macho-repeat" "$artifacts/hotspotshade-macos-arm64.bin"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 0 "$status" "a Mach-O with repeated load-command rows must pass the audit"
  expect_text "the binary is a Mach-O arm64 executable" \
    "the audit must keep repeated od rows in the load-command length check"

  # The standalone binary must declare the macOS platform. An iOS platform
  # declaration must not pass as the macOS release binary.
  cp "$work/macho-valid" "$artifacts/hotspotshade-macos-arm64.bin"
  patch_bytes "$artifacts/hotspotshade-macos-arm64.bin" 136 '\002\000\000\000'
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an iOS platform declaration in the macOS binary must fail"
  expect_text "does not declare the expected macos platform" \
    "the audit must check the binary build platform"
  cp "$work/macho-valid" "$artifacts/hotspotshade-macos-arm64.bin"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # A wrong architecture must fail.
  printf '\xcf\xfa\xed\xfe\x07\x00\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00' > "$artifacts/hotspotshade-macos-arm64.bin"
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an x86_64 binary must fail the audit"
  expect_text "arm64 only" "the audit must explain the arm64 policy"
  printf '\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x06\x00\x00\x00' > "$artifacts/hotspotshade-macos-arm64.bin"
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "an arm64 Mach-O dylib must not pass as an executable"
  expect_text "not a Mach-O arm64 executable" "the audit must check the Mach-O file type"

  # A header alone is not an executable. The load commands and segment
  # extents must fit inside the file.
  write_test_macho "$work/full-macho"
  head -c 16 "$work/full-macho" > "$artifacts/hotspotshade-macos-arm64.bin"
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "a truncated Mach-O header must fail the audit"
  expect_text "implausibly truncated" "the audit must reject a truncated Mach-O file"
  write_test_macho "$artifacts/hotspotshade-macos-arm64.bin"
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # A strict artifact audit must fail closed on the standalone binary, which
  # carries no in-band version, even when both app versions are aligned.
  audit_status --artifacts "$artifacts" --require-aligned-versions
  expect_status 1 "$status" "a strict artifact audit must fail closed on the unverified standalone binary version"
  expect_text "standalone binary carries no readable version" \
    "the audit must name the unverified standalone binary version"

  # An app version that does not match the engine must fail the strict audit.
  cp "$work/ipa/Payload/HotspotProxy.app/Info.plist" "$work/ipa-plist.xml"
  sed 's/9\.9\.9/1.0.0/' "$work/ipa-plist.xml" > "$work/ipa/Payload/HotspotProxy.app/Info.plist"
  (cd "$work/ipa" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  audit_status --artifacts "$artifacts"
  expect_status 0 "$status" "a plain artifact audit reports app version drift as a warning"
  expect_text "version drift: HotspotShade-iOS-unsigned.ipa: CFBundleShortVersionString is 1.0.0" \
    "the plain audit must name the app version drift"
  audit_status --artifacts "$artifacts" --require-aligned-versions
  expect_status 1 "$status" "a strict artifact audit must fail on app version drift"
  expect_text "version drift: HotspotShade-iOS-unsigned.ipa: CFBundleShortVersionString is 1.0.0" \
    "the strict audit must fail on the drifted app version"
  cp "$work/ipa-plist.xml" "$work/ipa/Payload/HotspotProxy.app/Info.plist"
  (cd "$work/ipa" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # A binary Info.plist needs plutil. Without it the version cannot be
  # verified, so a strict audit fails closed. On a host with plutil the same
  # binary plist is read, and only the standalone binary remains a blocker.
  if command -v plutil >/dev/null 2>&1 &&
     plutil -convert binary1 "$work/ipa/Payload/HotspotProxy.app/Info.plist" >/dev/null 2>&1; then
    (cd "$work/ipa" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts" --require-aligned-versions
    expect_status 1 "$status" "a strict artifact audit with a readable binary plist still fails on the standalone binary"
    expect_text "standalone binary carries no readable version" \
      "the audit must keep the standalone binary blocker"
    expect_no_text "HotspotShade-iOS-unsigned.ipa: the artifact version cannot be verified" \
      "plutil must let the audit verify the binary app plist version"
  else
    printf 'bplist00\000\000\000\000\000\000\000\000' \
      > "$work/ipa/Payload/HotspotProxy.app/Info.plist"
    (cd "$work/ipa" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
    sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
    audit_status --artifacts "$artifacts" --require-aligned-versions
    expect_status 1 "$status" "a strict artifact audit must fail closed on an unreadable binary plist"
    expect_text "HotspotShade-iOS-unsigned.ipa: the artifact version cannot be verified" \
      "the audit must name the unverified binary plist version"
  fi
  cp "$work/ipa-plist.xml" "$work/ipa/Payload/HotspotProxy.app/Info.plist"
  (cd "$work/ipa" && zip -qr "$artifacts/HotspotShade-iOS-unsigned.ipa" Payload)
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null

  # A tampered artifact must fail the manifest check.
  sh "$tree/scripts/release_manifest.sh" "$artifacts" >/dev/null
  printf 'extra\n' >> "$artifacts/HotspotShade-unsigned.zip"
  set +e
  out=$(sh "$tree/scripts/release_manifest.sh" --verify "$artifacts" 2>&1)
  status=$?
  set -e
  expect_status 1 "$status" "a tampered artifact must fail the manifest check"
  expect_text "MISMATCH" "the manifest check must name the tampered file"
  audit_status --artifacts "$artifacts"
  expect_status 1 "$status" "the audit must reject a tampered artifact set"
  expect_text "digest mismatch" "the audit must detect the changed digest"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures release pipeline test(s) failed." >&2
  exit 1
fi
echo "Release pipeline tests passed."
