#!/bin/sh
# Check the version fields inside finished release artifacts.
#
# scripts/release_audit.sh checks source metadata. This script reads the
# artifact bytes and compares what the artifacts say about themselves with the
# release version. It never extracts a whole archive, never runs an artifact,
# and never uses the network, a device, a route, or a signing key. The private
# temporary directory holds one plist, bounded ZIP metadata and header slices,
# and at most one bundled engine within the 1 GiB data bound. The script removes that directory on every exit,
# including HUP, INT, and TERM.
#
# Scope. This check reads version fields and archive structure. It does not
# validate app identity (CFBundleIdentifier), code signing, notarization,
# entitlements, the provisioning profile, or the origin of the bytes. A PASS
# says only that the version fields this reader understands agree with the
# expected version.
#
# Usage:
#   scripts/artifact_versions.sh (--expected-version X.Y.Z | --repo-root DIR)
#                                [--tag vX.Y.Z] [--allow-unverified]
#                                (--artifacts DIR | [--ipa FILE] [--mac-zip FILE]
#                                                   [--mac-binary FILE])
#
#   --expected-version V   The release version, for example 0.1.0.
#   --repo-root DIR        Read the version from DIR/rust/Cargo.toml instead.
#   --tag TAG              Also require TAG to equal v followed by the version.
#   --artifacts DIR        Check the fixed release set in DIR:
#                            HotspotShade-iOS-unsigned.ipa
#                            HotspotShade-unsigned.zip
#                            hotspotshade-macos-arm64.bin
#                          A missing or non-regular file is a failure. Every
#                          file is still checked after another one fails, and
#                          the summary always prints.
#   --ipa, --mac-zip, --mac-binary
#                          Check one file. Use these in a job that holds one
#                          artifact.
#   --allow-unverified     Exit 0 when nothing failed but some version could
#                          not be verified. The UNVERIFIED lines still print.
#                          This flag never turns an UNVERIFIED result into a
#                          PASS and never excuses a malformed artifact.
#
# What each artifact can prove:
#   IPA          CFBundleShortVersionString in the one Payload/NAME.app/Info.plist
#                (binary or XML plist). Verified.
#   macOS zip    CFBundleShortVersionString in the one NAME.app/Contents/Info.plist
#                (binary or XML plist). Verified. The zip must also hold the
#                engine NAME.app/Contents/Resources/bin/hotspotshade. The engine
#                must have a little-endian 64-bit arm64 Mach-O executable header
#                and at least 4096 bytes. The engine carries no version field this
#                check can trust, so its version is UNVERIFIED.
#   macOS binary The binary must have a little-endian 64-bit arm64 Mach-O
#                executable header and at least 4096 bytes. A Rust release build carries
#                no version field that this script can trust. The only strings
#                that hold the number come from embedded web assets, which are
#                not the Cargo version. The version is UNVERIFIED. The script
#                does not run the binary.
#
# Payloads are streamed through Perl Compress::Raw::Zlib. The checker fails
# closed if Perl or the module is unavailable, and it names which one. The total
# uncompressed size is limited to 1 GiB. Every data failure names the entry and
# the condition, such as a declared size, a stream that did not end, trailing
# compressed bytes, a size mismatch, or a CRC mismatch. It checks command
# framing, not Mach-O command semantics or executability.
#
# ZIP structure. The script does not trust unzip's central-directory listing.
# It reads the end-of-central-directory record, every central-directory entry,
# and every local file header from the raw bytes, then requires them to agree.
# Each local header must be exactly the next entry in the file, its name, flags,
# method, CRC, and sizes must equal the central-directory values, and the last
# local entry must end exactly where the central directory starts. An entry that
# exists in only one place is refused. A data descriptor (general-purpose flag
# bit 3, as ditto writes) is read and its CRC and sizes must match the central
# directory. This closes the disagreement where a central-directory reader sees
# one plist and a streaming extractor such as bsdtar sees another.
#
# The archive is refused when it is larger than 1 GiB, holds more than 20000
# entries, has a central directory larger than 4194304 bytes, has an archive or
# entry comment, is multi-disk, uses a ZIP64 field, locator, or sentinel, is
# encrypted or uses strong encryption, or uses a compression method other than
# stored or deflate.
# Unknown extra fields are refused; only the timestamp and Unix-owner fields
# 0x5455, 0x5855, 0x7855, and 0x7875 are read. The version-needed field must be from 10
# through 45. Only Unix-made entries are accepted. A symbolic link, device,
# socket, or other special type is refused, and a name that ends in a slash
# must be a directory with zero sizes while every other name must be a regular
# file. Setuid, setgid, and sticky bits are refused. A set DOS directory bit
# must agree with the name.
#
# Name rules. A name fails when it has a byte outside printable ASCII, a NUL,
# a question mark, a backslash, a colon, a drive letter, a glob character, a
# double quote, angle brackets, a pipe, or an asterisk. It fails when it is
# absolute, longer than 512 bytes, has an empty, "." or ".." component, starts
# a component with a hyphen, has a component that ends with a dot or a space,
# or uses a Windows reserved device name (CON, PRN, AUX, NUL, CLOCK$, COM1-9,
# LPT1-9, CONIN$, CONOUT$). Two names fail when they are identical, differ only
# in case, or one is both a file and a directory. The path component count is
# capped at 64. The archive is refused when its combined path prefixes exceed
# 200000 prefixes or 33554432 prefix bytes, so a hostile name cannot make the
# reader allocate multi-gigabyte maps.
#
# Plist rules. The reader is stricter than the platform on purpose, and any
# doubt is a failure. It reads ASCII XML text (a UTF-8 declaration is accepted)
# and bplist00 files. Non-ASCII keys are not matched and non-ASCII values do
# not compare. It skips comments and processing instructions between elements;
# a comment or processing instruction inside a leaf is refused. The XML
# declaration, when present, must be the first construct, must name version
# 1.0, and must not name an encoding
# other than UTF-8. The XML root must have exactly one attribute: version 1.0,
# in single or double quotes, with optional whitespace around the equals sign.
# A missing version is refused even though the Apple DTD supplies a default.
# It refuses a second XML declaration, a declaration after
# another construct, UTF-16 and UTF-32 text (a duplicate key cannot be ruled
# out), a byte order mark, CDATA, a DOCTYPE internal subset, an entity in a
# top-level key, text outside an element, an unbalanced or unknown element, and
# a key without a value. It compares the version text exactly, with no
# whitespace trimming, so a padded value fails. In XML, a top-level key that
# equals the wanted key after trimming whitespace, but is not equal, fails as
# ambiguous. A top-level key that appears twice fails, in XML and in bplist00,
# including a key written as ASCII or UTF-16 string objects. A version
# value that is not a string fails. A plist larger than 262144 bytes is
# refused. Binary UTF-8 (0x7) string objects are refused. The extracted plist
# must match the stored CRC and uncompressed size. This is a version extractor,
# not a full plist validator: unrelated binary values, object graph consistency,
# and XML value syntax are not fully validated. Inputs and tools must remain
# stable during the check; a same-user attacker can change them or scratch files.
#
# Exit codes: 0 all checks passed (and, without --allow-unverified, nothing
# was unverified); 1 a check failed; 2 bad usage; 3 nothing failed but some
# version is UNVERIFIED; 129, 130, 143 the script received HUP, INT, or TERM.
#
# Programs: POSIX sh, awk, od, tail, head, cut, tr, grep, sort, sed, wc,
# gzip, unzip, and Perl with Compress::Raw::Zlib. Set HS_AWK to test another awk implementation. The default
# is awk.
set -eu

# Byte-wise matching and sorting. A hostile name must not change a range
# or a case rule through the locale.
LC_ALL=C
export LC_ALL

# Bounds. A plist inside an artifact is small. Anything larger is rejected.
max_plist_bytes=262144
max_entries=20000
max_entry_name=512
max_path_components=64
max_total_prefixes=200000
max_total_prefix_bytes=33554432
max_total_name_bytes=10485760
max_archive_bytes=1073741824
max_cd_bytes=4194304
max_extra_bytes=4096
max_local_header_bytes=$((30 + max_entry_name + max_extra_bytes))
min_macho_bytes=4096
max_macho_commands=1048576

expected=""
repo_root=""
tag=""
artifacts=""
ipa=""
mac_zip=""
mac_binary=""
allow_unverified=0

# Print a value from an artifact only when it is short and plain. A hostile
# plist must not put control characters or escape codes in the log.
printable() {
  case "$1" in
    ''|*[!A-Za-z0-9._\$\(\)\ -]*) printf '<not printable>' ;;
    *) [ "${#1}" -le 64 ] && printf '%s' "$1" || printf '<too long>' ;;
  esac
}

# Print a short filename label without control characters or escape codes.
label() {
  case "$1" in
    '') printf '<unnamed>' ;;
    *) printf '%s' "$1" | tr -c 'A-Za-z0-9._ -' '?' | cut -c1-80 ;;
  esac
}

# The same for a path, which keeps the directory separators readable.
label_path() {
  case "$1" in
    '') printf '<unnamed>' ;;
    *) printf '%s' "$1" | tr -c 'A-Za-z0-9._/ -' '?' | cut -c1-120 ;;
  esac
}

usage() {
  sed -n '2,/^set -eu$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --expected-version|--repo-root|--tag|--artifacts|--ipa|--mac-zip|--mac-binary)
      [ $# -ge 2 ] && [ -n "$2" ] || { echo "$1 needs a nonempty value" >&2; exit 2; }
      case "$1" in
        --expected-version) expected=$2 ;;
        --repo-root) repo_root=$2 ;;
        --tag) tag=$2 ;;
        --artifacts) artifacts=$2 ;;
        --ipa) ipa=$2 ;;
        --mac-zip) mac_zip=$2 ;;
        --mac-binary) mac_binary=$2 ;;
      esac
      shift 2
      ;;
    --allow-unverified) allow_unverified=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $(label "$1")" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -n "$artifacts" ] && { [ -n "$ipa" ] || [ -n "$mac_zip" ] || [ -n "$mac_binary" ]; }; then
  echo "use --artifacts or the single-file options, not both" >&2
  exit 2
fi
if [ -z "$artifacts" ] && [ -z "$ipa" ] && [ -z "$mac_zip" ] && [ -z "$mac_binary" ]; then
  echo "name at least one artifact" >&2
  exit 2
fi
if [ -n "$expected" ] && [ -n "$repo_root" ]; then
  echo "use --expected-version or --repo-root, not both" >&2
  exit 2
fi
if [ -z "$expected" ] && [ -z "$repo_root" ]; then
  echo "give --expected-version or --repo-root" >&2
  exit 2
fi

passes=0
failures=0
unverified=0
pass() { passes=$((passes + 1)); printf 'PASS  %s\n' "$1"; }
fail() { failures=$((failures + 1)); printf 'FAIL  %s\n' "$1"; }
unver() { unverified=$((unverified + 1)); printf 'UNVERIFIED  %s\n' "$1"; }

is_version() {
  # X.Y.Z with decimal parts, no leading zero rules, bounded length.
  case "$1" in
    ''|*[!0-9.]*|.*|*.|*..*) return 1 ;;
  esac
  [ "${#1}" -le 32 ] || return 1
  printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'
}

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  return 0
}

awk_bin=${HS_AWK:-awk}
if ! command -v "$awk_bin" >/dev/null 2>&1; then
  echo "cannot run awk: $(printable "$awk_bin")" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Work directory and signals
# ---------------------------------------------------------------------------

# A trap that does not exit lets the script keep running after the signal.
# Each signal trap exits with the conventional status, and the EXIT trap
# removes the work directory on every path.
work=""
cleanup() {
  if [ -n "$work" ]; then
    rm -rf "$work"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------
# Expected version
# ---------------------------------------------------------------------------

if [ -n "$repo_root" ]; then
  manifest="$repo_root/rust/Cargo.toml"
  case "$manifest" in
    /*) ;;
    *) manifest="./$manifest" ;;
  esac
  if [ ! -f "$manifest" ]; then
    echo "cannot read $(label_path "$manifest")" >&2
    exit 2
  fi
  expected=$("$awk_bin" '
    /"""|\047\047\047/ { bad = 1 }
    /^[[:space:]]*\[/ {
      in_package = ($0 ~ /^[[:space:]]*\[package\][[:space:]]*(#.*)?$/)
      if (in_package) packages++
      next
    }
    in_package && /^[[:space:]]*version[[:space:]]*=/ {
      versions++
      if ($0 !~ /^[[:space:]]*version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"[[:space:]]*(#.*)?$/) bad = 1
      else { split($0, parts, "\""); version = parts[2] }
    }
    END {
      if (packages != 1 || versions != 1 || bad) exit 1
      print version
    }
  ' "$manifest") || expected=""
fi
if ! is_version "$expected"; then
  echo "the expected version must look like X.Y.Z: $(printable "$expected")" >&2
  exit 2
fi
pass "expected release version: $expected"

if [ -n "$tag" ]; then
  if [ "$tag" = "v$expected" ]; then
    pass "tag $(printable "$tag") matches the expected version"
  else
    fail "tag $(printable "$tag") does not equal v$expected"
  fi
fi

echo "Scope: this check reads version fields and archive structure. It does not verify app identity, code signing, notarization, entitlements, or the origin of the bytes."

work=$(mktemp -d "${TMPDIR:-/tmp}/hs-artver.XXXXXXXX")
case "$work" in
  /*) ;;
  *) work="./$work" ;;
esac

# ---------------------------------------------------------------------------
# Plist reader (awk, no plutil, works on Linux and macOS)
# ---------------------------------------------------------------------------

# plist_read FILE KEY
# Print one line. "OK VALUE" when KEY appears exactly once in the top-level
# dictionary with a string value. "ERR REASON" for every other outcome,
# including a parse problem. Reads XML plists and bplist00 files. Nothing is
# evaluated or extracted.
plist_read() {
  pv_file=$1
  pv_key=$2
  # These files are private scratch space. The caller must supply a stable file;
  # same-user mutation of the file, scratch directory, or tools is not excluded.
  if [ ! -f "$pv_file" ] || [ -L "$pv_file" ]; then
    echo "ERR the plist is not a regular non-symlink file"; return 0
  fi
  pv_size=$(wc -c < "$pv_file") || { echo "ERR cannot measure the plist"; return 0; }
  set -- $pv_size
  case ${1-} in ''|*[!0-9]*) echo "ERR invalid plist size"; return 0 ;; esac
  [ "$#" -eq 1 ] && [ "$1" -le "$max_plist_bytes" ] || { echo "ERR the plist is too large"; return 0; }
  pv_size=$1
  # Each producer completes before its consumer starts. Count every decoded byte,
  # including bytes after an otherwise valid plist, against the original size.
  if ! od -An -v -tu1 "$pv_file" > "$work/plist.od"; then
    echo "ERR cannot read plist bytes"; return 0
  fi
  if ! "$awk_bin" -v expected="$pv_size" '
    { for (i=1; i<=NF; i++) {
        if ($i !~ /^[0-9]+$/ || $i+0 > 255) exit 1
        b=$i+0; n++; if (n<=8) h=h sprintf("%c", b)
        if (b==0) nul++; if (b==60) lt++
      } }
    END { if (n != expected) exit 1; print (h == "bplist00" ? 1 : 0), (nul+0), (lt+0), (h ~ /^bplist/ ? 1 : 0) }
  ' "$work/plist.od" > "$work/plist.meta"; then
    echo "ERR incomplete plist byte read"; return 0
  fi
  if ! read -r pv_bin pv_nul pv_lt pv_bprefix < "$work/plist.meta"; then
    echo "ERR cannot inspect plist bytes"; return 0
  fi
  if [ "$pv_bprefix" -eq 1 ] && [ "$pv_bin" -eq 0 ]; then
    echo "ERR an unsupported binary plist version"; return 0
  fi
  if [ "$pv_bin" -eq 1 ]; then
    if ! "$awk_bin" -v want="$pv_key" '
      { for (i = 1; i <= NF; i++) b[n++] = $i + 0 }
      function err(msg) { print "ERR " msg; exit }
      function be(off, len,   v, k) {
        v = 0
        for (k = 0; k < len; k++) v = v * 256 + b[off + k]
        return v
      }
      # Read an integer object (marker 0x1N) at off. Sets int_len and returns the value.
      function read_int(off,   sz) {
        if (off >= n) return -1
        if (int(b[off] / 16) != 1) return -1
        sz = 2 ^ (b[off] % 16)
        if (sz > 4 || off + 1 + sz > n) return -1
        int_len = 1 + sz
        return be(off + 1, sz)
      }
      # Decode the length nibble at off, with the extended int form.
      # Sets hdr_len (marker plus extension) and returns the length.
      function read_len(off,   l, e) {
        l = b[off] % 16
        hdr_len = 1
        if (l == 15) {
          e = read_int(off + 1)
          if (e < 0) return -1
          hdr_len = 1 + int_len
          return e
        }
        return l
      }
      function obj_off(ref,   o) {
        if (ref < 0 || ref >= nobj) return -1
        o = be(tbl + ref * osz, osz)
        if (o < 8 || o >= tbl) return -1
        return o
      }
      # String object at ref: ASCII (0x5N) or UTF-16 (0x6N).
      # Sets sval. A character outside printable ASCII becomes a control
      # byte that never equals the wanted key. Returns the type nibble, 0
      # when the object is not a string, and -1 when it is malformed.
      function str_at(ref,   o, t, l, k, c, w, p) {
        sbad = 0
        o = obj_off(ref)
        if (o < 0) return -1
        t = int(b[o] / 16)
        if (t < 5 || t > 6) return 0
        l = read_len(o)
        if (l < 0 || l > 4096) return -1
        w = (t == 6) ? 2 : 1
        if (o + hdr_len + l * w > tbl) return -1
        sval = ""
        for (k = 0; k < l; k++) {
          p = o + hdr_len + k * w
          if (t == 6) {
            c = b[p + 1]
            if (b[p] != 0) c = 1
          } else {
            c = b[p]
          }
          if (c < 32 || c > 126) { c = 1; sbad = 1 }
          sval = sval sprintf("%c", c)
        }
        return t
      }
      END {
        if (n < 40) err("the binary plist is too short")
        t0 = n - 32
        osz = b[t0 + 6]; rsz = b[t0 + 7]
        nobj = be(t0 + 8, 8); top = be(t0 + 16, 8); tbl = be(t0 + 24, 8)
        if (osz < 1 || osz > 4 || rsz < 1 || rsz > 4) err("the binary plist trailer is invalid")
        if (nobj < 1 || nobj > 100000 || tbl + nobj * osz > t0) err("the binary plist trailer is invalid")
        for (j = 0; j < nobj; j++) {
          object = obj_off(j)
          if (object < 0) err("an object offset is invalid")
          if (int(b[object] / 16) == 7) err("a UTF-8 binary string is unsupported")
        }
        o = obj_off(top)
        if (o < 0 || int(b[o] / 16) != 13) err("the top-level object is not a dictionary")
        cnt = read_len(o)
        if (cnt < 0 || cnt > 4096) err("the top-level dictionary size is invalid")
        base = o + hdr_len
        if (base + 2 * cnt * rsz > tbl) err("the top-level dictionary is truncated")
        found = 0
        nonstr = 0
        val = ""
        for (i = 0; i < cnt; i++) {
          kt = str_at(be(base + i * rsz, rsz))
          if (kt < 0) err("a dictionary key is malformed")
          if (kt == 0) err("a dictionary key is not a string")
          if (sbad) err("a dictionary key has a non-printable byte")
          if (sval == want) {
            found++
            vt = str_at(be(base + (cnt + i) * rsz, rsz))
            if (vt < 0) err("a dictionary value is malformed")
            if (vt == 0) nonstr = 1
            else val = sval
          }
        }
        if (found == 0) err("the key is missing")
        if (found > 1) err("the key appears more than once")
        if (nonstr) err("the value is not a string")
        print "OK " val
      }
    ' "$work/plist.od" > "$work/plist.result"; then
      echo "ERR cannot parse binary plist"; return 0
    fi
  else
    if [ "$pv_nul" -ne 0 ]; then
      echo "ERR the plist has NUL bytes (UTF-16 or UTF-32 text is not read)"
      return 0
    fi
    # One tag per line, then a small state machine over the lines. Newlines
    # and tabs inside the text become spaces first.
    if ! tr '\n\r\t' '   ' < "$pv_file" > "$work/plist.tr"; then
      echo "ERR cannot normalize plist text"; return 0
    fi
    pv_count=$(wc -c < "$work/plist.tr") || { echo "ERR cannot measure normalized plist"; return 0; }
    [ "$pv_count" -eq "$pv_size" ] 2>/dev/null || { echo "ERR incomplete plist text read"; return 0; }
    if ! sed 's/</\
</g' "$work/plist.tr" > "$work/plist.sed"; then
      echo "ERR cannot split plist text"; return 0
    fi
    pv_count=$(wc -c < "$work/plist.sed") || { echo "ERR cannot measure split plist"; return 0; }
    [ "$pv_count" -eq "$((pv_size + pv_lt))" ] 2>/dev/null || { echo "ERR incomplete plist text split"; return 0; }
    if ! "$awk_bin" -v want="$pv_key" '
      BEGIN { xml_decl_allowed = 1 }
      function bad(msg) { print "ERR " msg; failed = 1; exit }
      function trim(s) { gsub(/^ +| +$/, "", s); return s }
      function ws_only(t) { return t ~ /^ *$/ }
      function need_ws(t) { if (!ws_only(t)) bad("text outside an element") }
      # A value (a leaf or the start of a container) in the current position.
      function value(kind, text,   d) {
        d = depth
        if (d == 0) {
          if (root_seen) bad("more than one top-level value")
          root_seen = 1
          if (kind != "dict") bad("the top-level value is not a dictionary")
          return
        }
        if (ctype[d] == "dict") {
          if (kstate[d] != 1) bad("a dictionary value has no key")
          kstate[d] = 0
          if (d == 1 && curkey == want) {
            found++
            if (kind == "string") val = text
            else nonstr = 1
          }
        }
      }
      function leaf(name, text) {
        if (text ~ /[[:cntrl:]]/) bad("an element has a control character")
        if (name == "key") {
          if (depth < 1 || ctype[depth] != "dict" || kstate[depth] != 0) bad("a key is out of place")
          kstate[depth] = 1
          if (depth == 1) {
            if (index(text, "&") > 0) bad("a top-level key has an entity")
            if (text != want && trim(text) == want) bad("a top-level key has surrounding whitespace")
            curkey = text
          }
          return
        }
        value(name, text)
      }
      function handle_tag(tag, text,   closing, selfc, name, attrs, sp) {
        closing = 0; selfc = 0
        if (substr(tag, 1, 1) == "/") { closing = 1; tag = substr(tag, 2) }
        if (substr(tag, length(tag), 1) == "/") { selfc = 1; tag = substr(tag, 1, length(tag) - 1) }
        sp = index(tag, " ")
        if (sp) { name = substr(tag, 1, sp - 1); attrs = trim(substr(tag, sp + 1)) }
        else { name = tag; attrs = "" }
        if (cur_leaf != "") {
          if (!(closing && !selfc && attrs == "" && name == cur_leaf)) bad("an element inside <" cur_leaf ">")
          leaf(cur_leaf, leaf_text)
          cur_leaf = ""
          need_ws(text)
          return
        }
        if (closing && (selfc || attrs != "")) bad("a malformed closing tag")
        if (attrs != "" && name != "plist") bad("an attribute on <" name ">")
        if (name == "plist") {
          if (closing) {
            if (!in_plist || depth != 0 || !root_seen || done) bad("an unbalanced </plist>")
            done = 1
          } else {
            if (in_plist || selfc) bad("an unexpected <plist>")
            if (attrs !~ /^version *= *("1\.0"|\0471\.0\047)$/) bad("the plist version attribute is invalid")
            in_plist = 1
          }
          need_ws(text)
          return
        }
        if (done || !in_plist) bad("an element outside the plist element")
        if (name == "dict" || name == "array") {
          if (closing) {
            if (depth < 1 || ctype[depth] != name) bad("an unbalanced </" name ">")
            if (ctype[depth] == "dict" && kstate[depth] == 1) bad("a key has no value")
            depth--
          } else {
            value(name, "")
            if (!selfc) {
              depth++
              if (depth > 64) bad("the plist is nested too deeply")
              ctype[depth] = name
              kstate[depth] = 0
            }
          }
          need_ws(text)
          return
        }
        if (name == "key" || name == "string" || name == "integer" || name == "real" || name == "date" || name == "data") {
          if (closing) bad("an unbalanced </" name ">")
          if (selfc) { leaf(name, ""); need_ws(text) }
          else { cur_leaf = name; leaf_text = text }
          return
        }
        if (name == "true" || name == "false") {
          if (closing || !selfc) bad("a malformed <" name ">")
          value(name, "")
          need_ws(text)
          return
        }
        bad("an unknown element <" name ">")
      }
      {
        line = $0
        if (NR == 1) {
          if (!ws_only(line)) bad("text before the first tag (a byte order mark is not read)")
          next
        }
        if (in_comment || in_pi) {
          if (in_comment) { p = index(line, "-->"); len = 3 }
          else { p = index(line, "?>"); len = 2 }
          if (!p) next
          in_comment = 0; in_pi = 0
          need_ws(substr(line, p + len))
          next
        }
        if (substr(line, 1, 4) == "<!--") {
          if (cur_leaf != "") bad("a comment inside <" cur_leaf ">")
          if (substr(line, 1, 5) == "<!-->" || substr(line, 1, 6) == "<!--->") bad("a malformed comment")
          xml_decl_allowed = 0
          p = index(substr(line, 5), "-->")
          if (p) need_ws(substr(line, 4 + p + 3))
          else in_comment = 1
          next
        }
        if (substr(line, 1, 9) == "<![CDATA[") bad("CDATA is not read")
        if (substr(line, 1, 9) == "<!DOCTYPE") {
          if (cur_leaf != "" || in_plist || seen_doctype) bad("a misplaced DOCTYPE")
          seen_doctype = 1
          xml_decl_allowed = 0
          if (index(line, "[") > 0) bad("a DOCTYPE internal subset is not read")
          p = index(line, ">")
          if (!p) bad("an unterminated DOCTYPE")
          need_ws(substr(line, p + 1))
          next
        }
        if (substr(line, 1, 2) == "<!") bad("an unsupported declaration")
        if (substr(line, 1, 2) == "<?") {
          if (cur_leaf != "") bad("a processing instruction inside <" cur_leaf ">")
          lower = tolower(line)
          is_decl = (substr(line, 1, 6) == "<?xml " || substr(line, 1, 6) == "<?xml?")
          if (is_decl) {
            if (xml_decl_seen) bad("more than one XML declaration")
            if (!xml_decl_allowed) bad("the XML declaration is not first")
            xml_decl_seen = 1
            xml_decl_allowed = 0
            if (lower !~ /version *= *["'"'"']1\.0["'"'"']/) bad("the XML declaration must name version 1.0")
            if (index(lower, "encoding") > 0 && lower !~ /encoding *= *["'"'"']utf-8["'"'"']/) bad("an XML encoding other than UTF-8")
          } else {
            if (tolower(substr(line, 1, 5)) == "<?xml" &&
                (substr(line, 6, 1) == " " || substr(line, 6, 1) == "?"))
              bad("a malformed XML declaration")
            xml_decl_allowed = 0
          }
          p = index(line, "?>")
          if (p) need_ws(substr(line, p + 2))
          else in_pi = 1
          next
        }
        if (substr(line, 1, 1) != "<") bad("text before a tag")
        xml_decl_allowed = 0
        gt = index(line, ">")
        if (!gt) bad("an unterminated tag")
        handle_tag(substr(line, 2, gt - 2), substr(line, gt + 1))
      }
      END {
        if (failed) exit
        if (in_comment || in_pi) bad("an unterminated comment or processing instruction")
        if (cur_leaf != "") bad("an unterminated element")
        if (!done) bad("the plist element is not closed")
        if (found == 0) bad("the key is missing")
        if (found > 1) bad("the key appears more than once")
        if (nonstr) bad("the value is not a string")
        print "OK " val
      }
    ' "$work/plist.sed" > "$work/plist.result"; then
      echo "ERR cannot parse XML plist"; return 0
    fi
  fi
  if ! IFS= read -r pv_result < "$work/plist.result"; then
    echo "ERR cannot read plist result"; return 0
  fi
  printf "%s\n" "$pv_result"
}

# ---------------------------------------------------------------------------
# Mach-O reader
# ---------------------------------------------------------------------------

# crc32_file FILE: print the ZIP CRC-32 as a decimal. gzip writes the CRC-32
# and the input size in its 8-byte trailer, so this needs no extra program.
crc32_file() {
  cf_file=$1
  case "$cf_file" in
    /*) ;;
    *) cf_file="./$cf_file" ;;
  esac
  gzip -n -c "$cf_file" 2>/dev/null | tail -c 8 | head -c 4 | od -An -v -tu1 |
    "$awk_bin" 'NF == 4 { printf "%.0f\n", $1 + 256 * $2 + 65536 * $3 + 16777216 * $4 }'
}

# macho_check_header FILE FULLSIZE LABEL
# FILE holds up to the first 1 MiB plus header. FULLSIZE is the real size. Check a
# little-endian 64-bit arm64 Mach-O executable header. Every failure prints and
# returns 1.
macho_check_header() {
  mh_file=$1; mh_full=$2; mh_label=$3
  mh_size=$(wc -c < "$mh_file" | tr -d ' ')
  if [ "$mh_size" -lt 32 ]; then
    fail "$mh_label: cannot read a complete 32-byte Mach-O header"
    return 1
  fi
  if [ "$mh_full" -lt "$min_macho_bytes" ]; then
    fail "$mh_label: smaller than $min_macho_bytes bytes, so it cannot be a release Mach-O executable"
    return 1
  fi
  mh_res=$(od -An -v -tu1 "$mh_file" | "$awk_bin" -v full="$mh_full" '
    { for (i = 1; i <= NF; i++) b[n++] = $i + 0 }
    function u32(p) { return b[p] + 256 * b[p+1] + 65536 * b[p+2] + 16777216 * b[p+3] }
    function err(m) { print m; exit }
    END {
      if (n < 32) err("a short Mach-O header")
      if (u32(0) != 4277009103) err("not a little-endian 64-bit Mach-O file")
      if (u32(4) != 16777228) err("not an arm64 Mach-O file")
      st = u32(8)
      if (st != 0 && st != 1 && st != 2) err("an unsupported arm64 subtype")
      if (u32(12) != 2) err("not an executable Mach-O file")
      nc = u32(16)
      sc = u32(20)
      if (nc < 1 || nc > 4096) err("an invalid Mach-O load-command count")
      if (sc < 8 * nc) err("a Mach-O load-command size is too small")
      if (sc % 4 != 0) err("a Mach-O load-command size is not aligned")
      if (sc > 1048576) err("the Mach-O load commands exceed the byte bound")
      if (32 + sc > full || 32 + sc > n) err("the Mach-O load commands extend past the file")
      pos = 32
      for (j = 0; j < nc; j++) {
        if (pos + 8 > 32 + sc) err("a Mach-O load command is truncated")
        size = u32(pos + 4)
        if (size < 8 || size % 8 != 0 || pos + size > 32 + sc)
          err("a Mach-O load command has an invalid size")
        pos += size
      }
      if (pos != 32 + sc) err("the Mach-O load-command sizes do not add up")
      print "OK"
    }') || mh_res=""
  case "$mh_res" in
    OK) return 0 ;;
    *) fail "$mh_label: $mh_res"; return 1 ;;
  esac
}

# macho_check_file FILE LABEL: check the bounded header and load-command area.
macho_check_file() {
  mf_file=$1; mf_label=$2
  mf_size=$(wc -c < "$mf_file" | tr -d ' ')
  mf_head="$work/macho.$$"
  head -c $((32 + max_macho_commands)) "$mf_file" > "$mf_head"
  if macho_check_header "$mf_head" "$mf_size" "$mf_label"; then
    mf_rc=0
  else
    mf_rc=1
  fi
  rm -f "$mf_head"
  return "$mf_rc"
}

# ---------------------------------------------------------------------------
# Raw ZIP metadata reader
# ---------------------------------------------------------------------------

# zip_eocd FILE: print "EOCD<TAB>entries<TAB>cd_size<TAB>cd_offset<TAB>end<TAB>file_size"
# or "ERR<TAB>reason". The record must be the only one that ends at the file
# end, the archive must be single-disk, have no comment, and use no ZIP64.
zip_eocd() {
  ze_file=$1
  ze_size=$(wc -c < "$ze_file" | tr -d ' ')
  if [ "$ze_size" -gt "$max_archive_bytes" ]; then
    printf 'ERR the archive is larger than %s bytes\n' "$max_archive_bytes"
    return 0
  fi
  if [ "$ze_size" -lt 22 ]; then
    printf 'ERR the archive is too short to hold an end-of-central-directory record\n'
    return 0
  fi
  ze_tail=$ze_size
  [ "$ze_tail" -gt 65557 ] && ze_tail=65557
  ze_start=$((ze_size - ze_tail))
  tail -c "$ze_tail" "$ze_file" | od -An -v -tu1 |
    "$awk_bin" -v fsize="$ze_size" -v tailstart="$ze_start" \
      -v maxentries="$max_entries" -v maxcd="$max_cd_bytes" '
      { for (i = 1; i <= NF; i++) b[n++] = $i + 0 }
      function u16(p) { return b[p] + 256 * b[p+1] }
      function u32(p) { return b[p] + 256 * b[p+1] + 65536 * b[p+2] + 16777216 * b[p+3] }
      function err(m) { print "ERR " m; exit }
      END {
        if (n < 22) err("the end-of-central-directory record is missing")
        found = 0; e = -1
        for (p = 0; p + 22 <= n; p++) {
          if (b[p] == 80 && b[p+1] == 75 && b[p+2] == 5 && b[p+3] == 6) {
            clen = u16(p + 20)
            if (p + 22 + clen == n) { found++; e = p }
          }
        }
        if (found != 1) err("the end-of-central-directory record is missing or ambiguous")
        if (e >= 20 && b[e-20] == 80 && b[e-19] == 75 && b[e-18] == 6 && b[e-17] == 7)
          err("ZIP64 is not supported")
        if (u16(e + 4) != 0 || u16(e + 6) != 0) err("a multi-disk archive is not supported")
        n1 = u16(e + 8); n2 = u16(e + 10)
        cdsize = u32(e + 12); cdoff = u32(e + 16); clen = u16(e + 20)
        if (n1 != n2) err("the two entry counts in the end record disagree")
        if (clen != 0) err("an archive comment is not supported")
        if (n2 == 65535 || cdsize == 4294967295 || cdoff == 4294967295)
          err("ZIP64 is not supported")
        if (n2 == 0) err("the archive has no entries")
        if (n2 > maxentries) err("the archive has more than " maxentries " entries")
        if (cdsize > maxcd) err("the central directory is larger than " maxcd " bytes")
        if (cdsize < 46) err("the central directory is too small")
        eocdabs = tailstart + e
        if (cdoff + cdsize != eocdabs)
          err("the central directory does not end at the end-of-central-directory record")
        if (cdoff >= fsize) err("the central directory offset is outside the archive")
        print "EOCD " n2 " " cdsize " " cdoff " " eocdabs " " fsize
      }'
}

# zip_cd FILE CD_OFFSET CD_SIZE ENTRIES: print one E line per central-directory
# entry:
#   E idx flags method crc csize usize offset mode dos vneed extra_ids name_hex
# or ERR. The whole central directory is read because its size is bounded.
zip_cd() {
  zc_file=$1; zc_off=$2; zc_size=$3; zc_total=$4
  tail -c +$((zc_off + 1)) "$zc_file" | head -c "$zc_size" | od -An -v -tu1 |
    "$awk_bin" -v total="$zc_total" -v cdoff="$zc_off" -v cdsize="$zc_size" \
      -v maxname="$max_entry_name" -v maxextra="$max_extra_bytes" '
      { for (i = 1; i <= NF; i++) b[n++] = $i + 0 }
      function u16(p) { return b[p] + 256 * b[p+1] }
      function u32(p) { return b[p] + 256 * b[p+1] + 65536 * b[p+2] + 16777216 * b[p+3] }
      function err(m) { print "ERR " m; exit }
      function bit(v, k,   d) { d = 1; while (k-- > 0) d *= 2; return int(v / d) % 2 }
      function hexname(p, len,   i, s) {
        s = ""
        for (i = 0; i < len; i++) s = s sprintf("%02x", b[p+i])
        return s
      }
      function parse_extra(p, len,   q, eid, esz, ids, idstr) {
        q = 0; ids = ""
        while (q < len) {
          if (q + 4 > len) err("a malformed extra field")
          eid = u16(p + q); esz = u16(p + q + 2)
          if (q + 4 + esz > len) err("a malformed extra field")
          if (eid == 1) err("a ZIP64 extra field is not supported")
          if (eid == 28789) err("a Unicode path extra field is not supported")
          if (eid == 25461) err("a Unicode comment extra field is not supported")
          if (eid == 39169) err("an AES extra field is not supported")
          if (eid == 23) err("a strong-encryption extra field is not supported")
          if (eid != 21589 && eid != 22613 && eid != 30805 && eid != 30837)
            err("an unknown extra field is not supported")
          idstr = sprintf("%04x", eid)
          if (index("," ids ",", "," idstr ",")) err("a duplicate extra field")
          ids = ids (ids == "" ? "" : ",") idstr
          q += 4 + esz
        }
        return ids
      }
      END {
        if (n != cdsize) err("the central directory is truncated")
        p = 0; count = 0; prev = -1
        while (p < n) {
          if (n - p < 46) err("the central directory is truncated")
          if (u32(p) != 33639248) err("a central-directory signature is invalid")
          vmade = u16(p + 4); vneed = u16(p + 6); flags = u16(p + 8)
          method = u16(p + 10); crc = u32(p + 16); csize = u32(p + 20)
          usize = u32(p + 24); nlen = u16(p + 28); elen = u16(p + 30)
          clen = u16(p + 32); disk = u16(p + 34); eattr = u32(p + 38)
          off = u32(p + 42)
          if (int(vmade / 256) != 3) err("a non-Unix entry is not supported")
          if (vneed < 10 || vneed > 45) err("an unsupported version-needed value")
          if (disk != 0) err("a multi-disk entry is not supported")
          if (nlen < 1 || nlen > maxname) err("an entry name is empty or too long")
          if (elen > maxextra) err("an entry extra field is too long")
          if (clen != 0) err("an entry comment is not supported")
          if (p + 46 + nlen + elen > n) err("the central directory entry is truncated")
          if (bit(flags, 0)) err("an encrypted entry is not supported")
          if (bit(flags, 6)) err("a strongly encrypted entry is not supported")
          if (bit(flags, 13)) err("a masked local header is not supported")
          for (k = 0; k < 16; k++) {
            if (k == 1 || k == 2 || k == 3 || k == 11) continue
            if (bit(flags, k)) err("an unsupported general-purpose flag is set")
          }
          if (method != 0 && method != 8) err("an unsupported compression method")
          if (method == 0 && (bit(flags, 1) || bit(flags, 2)))
            err("a stored entry has deflate option flags")
          if (method == 0 && csize != usize) err("a stored entry has unequal sizes")
          if (csize == 4294967295 || usize == 4294967295 || off == 4294967295)
            err("ZIP64 is not supported")
          if (off < 0 || off >= cdoff) err("a local header offset is outside the data area")
          if (off <= prev) err("the central-directory offsets are not strictly increasing")
          prev = off
          if (off + 30 + nlen + csize > cdoff)
            err("a central-directory entry extends past the data area")
          mode = int(eattr / 65536)
          dos = eattr - mode * 65536
          type = int(mode / 4096)
          if (type == 4) isdir = 1
          else if (type == 8) isdir = 0
          else err("an entry is a special file type")
          if (int(mode / 512) % 8 != 0)
            err("an entry has setuid, setgid, or sticky bits")
          namedir = (b[p + 46 + nlen - 1] == 47)
          if (isdir != namedir) err("an entry name and its file type disagree")
          if (bit(dos, 4) && !isdir) err("the DOS directory bit disagrees with the entry")
          if (isdir && (csize != 0 || usize != 0))
            err("a directory entry has a nonzero size")
          ids = parse_extra(p + 46 + nlen, elen)
          nh = hexname(p + 46, nlen)
          printf "E|%d|%d|%d|%.0f|%d|%d|%d|%d|%d|%d|%s|%s\n", \
            count, flags, method, crc, csize, usize, off, mode, dos, vneed, ids, nh
          p += 46 + nlen + elen + clen
          count++
        }
        if (p != n) err("the central directory has trailing bytes")
        if (count != total) err("the central directory holds " count " entries, expected " total)
      }'
}

# zip_local FILE OFFSET VNEED FLAGS METHOD CRC CSIZE USIZE NAME_HEX NAME_BYTES EXTRA_IDS
# Print "OK data_start csize descriptor" or "ERR reason". The slice is bounded.
zip_local() {
  zl_file=$1; zl_off=$2; zl_vneed=$3; zl_flags=$4; zl_method=$5
  zl_crc=$6; zl_csize=$7; zl_usize=$8; zl_name=$9
  shift 9
  zl_namelen=$1; zl_ids=$2
  tail -c +$((zl_off + 1)) "$zl_file" | head -c "$max_local_header_bytes" | od -An -v -tu1 |
    "$awk_bin" -v eoff="$zl_off" -v evneed="$zl_vneed" -v eflags="$zl_flags" \
      -v emethod="$zl_method" -v ecrc="$zl_crc" -v ecsize="$zl_csize" \
      -v eusize="$zl_usize" -v ename="$zl_name" -v enamelen="$zl_namelen" \
      -v eids="$zl_ids" -v maxextra="$max_extra_bytes" '
      { for (i = 1; i <= NF; i++) b[n++] = $i + 0 }
      function u16(p) { return b[p] + 256 * b[p+1] }
      function u32(p) { return b[p] + 256 * b[p+1] + 65536 * b[p+2] + 16777216 * b[p+3] }
      function err(m) { print "ERR " m; exit }
      function bit(v, k,   d) { d = 1; while (k-- > 0) d *= 2; return int(v / d) % 2 }
      function hexname(p, len,   i, s) {
        s = ""
        for (i = 0; i < len; i++) s = s sprintf("%02x", b[p+i])
        return s
      }
      function parse_extra(p, len,   q, eid, esz, ids, idstr) {
        q = 0; ids = ""
        while (q < len) {
          if (q + 4 > len) err("a malformed local extra field")
          eid = u16(p + q); esz = u16(p + q + 2)
          if (q + 4 + esz > len) err("a malformed local extra field")
          if (eid == 1) err("a local ZIP64 extra field is not supported")
          if (eid == 28789) err("a local Unicode path extra field is not supported")
          if (eid == 25461) err("a local Unicode comment extra field is not supported")
          if (eid == 39169) err("a local AES extra field is not supported")
          if (eid == 23) err("a local strong-encryption extra field is not supported")
          if (eid != 21589 && eid != 22613 && eid != 30805 && eid != 30837)
            err("an unknown local extra field is not supported")
          idstr = sprintf("%04x", eid)
          if (index("," ids ",", "," idstr ",")) err("a duplicate local extra field")
          ids = ids (ids == "" ? "" : ",") idstr
          q += 4 + esz
        }
        return ids
      }
      END {
        if (n < 30) err("the local header is truncated")
        if (u32(0) != 67324752) err("the local header signature is invalid")
        vneed = u16(4); flags = u16(6); method = u16(8)
        crc = u32(14); csize = u32(18); usize = u32(22)
        nlen = u16(26); elen = u16(28)
        if (vneed != evneed) err("the local version-needed value differs from the central directory")
        if (flags != eflags) err("the local flags differ from the central directory")
        if (method != emethod) err("the local method differs from the central directory")
        if (nlen != enamelen) err("the local name length differs from the central directory")
        if (elen > maxextra) err("the local extra field is too long")
        if (30 + nlen + elen > n) err("the local header is truncated")
        if (hexname(30, nlen) != ename) err("the local name differs from the central directory")
        if (parse_extra(30 + nlen, elen) != eids)
          err("the local extra fields differ from the central directory")
        if (bit(flags, 3)) {
          if (crc != 0 || csize != 0 || usize != 0)
            err("a local header with a data descriptor must have zero sizes")
          print "OK " (eoff + 30 + nlen + elen) " " ecsize " 1"
        } else {
          if (crc != ecrc) err("the local CRC differs from the central directory")
          if (csize != ecsize) err("the local compressed size differs from the central directory")
          if (usize != eusize) err("the local uncompressed size differs from the central directory")
          print "OK " (eoff + 30 + nlen + elen) " " ecsize " 0"
        }
      }'
}

# zip_desc FILE DATA_END CRC CSIZE USIZE: print "OK descriptor_length" or ERR.
zip_desc() {
  zd_file=$1; zd_off=$2; zd_crc=$3; zd_csize=$4; zd_usize=$5
  tail -c +$((zd_off + 1)) "$zd_file" | head -c 16 | od -An -v -tu1 |
    "$awk_bin" -v ecrc="$zd_crc" -v ecsize="$zd_csize" -v eusize="$zd_usize" '
      { for (i = 1; i <= NF; i++) b[n++] = $i + 0 }
      function u32(p) { return b[p] + 256 * b[p+1] + 65536 * b[p+2] + 16777216 * b[p+3] }
      function err(m) { print "ERR " m; exit }
      END {
        if (n < 12) err("the data descriptor is truncated")
        if (n >= 16 && u32(0) == 134695760) { base = 4; dlen = 16 }
        else { base = 0; dlen = 12 }
        if (u32(base) != ecrc) err("the data descriptor CRC differs from the central directory")
        if (u32(base + 4) != ecsize) err("the data descriptor compressed size differs from the central directory")
        if (u32(base + 8) != eusize) err("the data descriptor uncompressed size differs from the central directory")
        print "OK " dlen
      }'
}

# zip_check_local FILE META CD_OFFSET: verify every local header is the next
# entry, ends where the next one starts, and the last one ends at CD_OFFSET.
# Print ERR on the first problem, otherwise nothing.
zip_check_local() {
  zcl_file=$1; zcl_meta=$2; zcl_cd=$3
  zcl_pos=0
  while IFS='|' read -r zcl_tag zcl_idx zcl_flags zcl_method zcl_crc \
    zcl_csize zcl_usize zcl_off zcl_mode zcl_dos zcl_vneed zcl_ids zcl_hex; do
    [ "$zcl_tag" = E ] || continue
    if [ "$zcl_off" -ne "$zcl_pos" ]; then
      printf 'ERR the local header at offset %s is not the next entry (expected %s)\n' \
        "$zcl_off" "$zcl_pos"
      return 0
    fi
    zcl_namelen=$((${#zcl_hex} / 2))
    zcl_res=$(zip_local "$zcl_file" "$zcl_off" "$zcl_vneed" "$zcl_flags" \
      "$zcl_method" "$zcl_crc" "$zcl_csize" "$zcl_usize" "$zcl_hex" \
      "$zcl_namelen" "$zcl_ids" || true)
    case "$zcl_res" in
      OK\ *)
        set -- $zcl_res
        zcl_data=$2; zcl_size=$3; zcl_desc=$4
        zcl_end=$((zcl_data + zcl_size))
        if [ "$zcl_end" -gt "$zcl_cd" ]; then
          printf 'ERR the local data for entry %s extends into the central directory\n' "$zcl_idx"
          return 0
        fi
        if [ "$zcl_desc" -eq 1 ]; then
          if [ $((zcl_end + 12)) -gt "$zcl_cd" ]; then
            printf 'ERR the data descriptor for entry %s extends into the central directory\n' "$zcl_idx"
            return 0
          fi
          zcl_dres=$(zip_desc "$zcl_file" "$zcl_end" "$zcl_crc" "$zcl_csize" "$zcl_usize" || true)
          case "$zcl_dres" in
            OK\ *)
              set -- $zcl_dres
              zcl_pos=$((zcl_end + $2))
              ;;
            ERR\ *)
              printf '%s\n' "$zcl_dres"
              return 0
              ;;
            *)
              printf 'ERR the data descriptor check did not answer\n'
              return 0
              ;;
          esac
        else
          zcl_pos=$zcl_end
        fi
        if [ "$zcl_pos" -gt "$zcl_cd" ]; then
          printf 'ERR the local data for entry %s extends into the central directory\n' "$zcl_idx"
          return 0
        fi
        ;;
      ERR\ *)
        printf '%s\n' "$zcl_res"
        return 0
        ;;
      *)
        printf 'ERR the local header check did not answer\n'
        return 0
        ;;
    esac
  done < "$zcl_meta"
  if [ "$zcl_pos" -ne "$zcl_cd" ]; then
    printf 'ERR the archive holds local data that the central directory does not list (%s bytes before the central directory)\n' \
      "$((zcl_cd - zcl_pos))"
  fi
}

# Verify every complete payload with bounded streaming decompression. The raw
# inflater must consume exactly the declared compressed bytes, reach its end,
# and produce exactly the declared size and CRC. Output is discarded in 64 KiB
# chunks. Total declared uncompressed data is capped at 1 GiB per archive.
# Print nothing on success. On failure print one "ERR reason" line that names
# the entry and the failed condition. A missing Perl, an unusable Perl, and a
# missing module have separate reasons. The caller treats any other output or a
# nonzero exit as a failure.
zip_check_data() {
  zd_archive=$1; zd_meta=$2
  if ! command -v perl >/dev/null 2>&1; then
    printf 'ERR the payload verifier is unavailable: perl is missing\n'
    return 0
  fi
  if ! perl -e 'exit 0' </dev/null >/dev/null 2>&1; then
    printf 'ERR the payload verifier is unavailable: perl cannot run\n'
    return 0
  fi
  if ! perl -MCompress::Raw::Zlib -e 'exit 0' </dev/null >/dev/null 2>&1; then
    printf 'ERR the payload verifier is unavailable: the Compress::Raw::Zlib module cannot load\n'
    return 0
  fi
  zd_rc=0
  zd_out=$(perl -MCompress::Raw::Zlib -e '
    use strict; use warnings;
    use Compress::Raw::Zlib qw(Z_OK Z_STREAM_END Z_BUF_ERROR crc32);
    sub fail { print "HSVERIFY $_[0]\n"; exit 1 }
    my ($archive, $meta) = @ARGV;
    open my $f, "<:raw", $archive or fail "archive open failed";
    open my $m, "<", $meta or fail "metadata open failed";
    my $total = 0;
    while (<$m>) {
      my @e = split /\|/;
      next unless $e[0] eq "E";
      my ($idx,$method,$crc,$cs,$us,$off) = @e[1,3,4,5,6,7];
      $total += $us;
      fail "entry $idx exceeds uncompressed data bound" if $total > 1073741824;
      seek($f, $off, 0) or fail "entry $idx seek failed";
      read($f, my $h, 30) == 30 or fail "entry $idx header read failed";
      my ($nl,$el) = unpack("x26vv", $h);
      seek($f, $off + 30 + $nl + $el, 0) or fail "entry $idx data seek failed";
      my ($left,$count,$sum,$ended) = ($cs,0,0,0);
      my $inflater;
      if ($method == 8) {
        my $status;
        ($inflater,$status) = Compress::Raw::Zlib::Inflate->new(
          -WindowBits => -15, -LimitOutput => 1, -Bufsize => 65536);
        fail "entry $idx inflater initialization failed" unless $status == Z_OK;
      }
      while ($left > 0) {
        my $want = $left > 65536 ? 65536 : $left;
        my $got = read($f, my $input, $want);
        fail "entry $idx data is truncated" unless defined($got) && $got == $want;
        $left -= $got;
        if ($method == 0) {
          $count += $got; $sum = crc32($input, $sum);
        } else {
          while (length($input)) {
            my $before = length($input);
            my $output = "";
            my $status = $inflater->inflate($input, $output);
            $count += length($output); $sum = crc32($output, $sum);
            fail "entry $idx exceeds declared size" if $count > $us;
            if ($status == Z_STREAM_END) {
              fail "entry $idx has trailing compressed bytes" if length($input) || $left;
              $ended = 1; last;
            }
            fail "entry $idx has invalid compressed data"
              unless ($status == Z_OK || $status == Z_BUF_ERROR)
                && (length($input) < $before || length($output));
          }
        }
        fail "entry $idx exceeds declared size" if $count > $us;
      }
      fail "entry $idx compressed stream did not end" if $method == 8 && !$ended;
      fail "entry $idx uncompressed size mismatch" if $count != $us;
      fail "entry $idx CRC mismatch" if $sum != $crc;
    }
  ' "$zd_archive" "$zd_meta" </dev/null 2>/dev/null) || zd_rc=$?
  case "$zd_out" in
    '')
      if [ "$zd_rc" -eq 0 ]; then
        return 0
      fi
      printf 'ERR the payload verifier failed without a reason\n'
      return 0
      ;;
    HSVERIFY\ *)
      zd_reason=${zd_out#HSVERIFY }
      printf 'ERR %s\n' "$(printf '%s\n' "$zd_reason" | head -n 1)"
      return 0
      ;;
    *)
      printf 'ERR the payload verifier printed unexpected output\n'
      return 0
      ;;
  esac
}

# zip_names META FILE: validate every name, file type, and collision. Print
# "V idx name isdir usize mode method" for each entry and "ERR reason" on the
# first problem. The name is decoded only after every byte is proven safe.
zip_names() {
  zn_meta=$1
  "$awk_bin" -F'|' -v maxname="$max_entry_name" \
    -v maxcomp="$max_path_components" -v maxprefix="$max_total_prefixes" \
    -v maxprefixbytes="$max_total_prefix_bytes" -v maxnamebytes="$max_total_name_bytes" '
    function err(m) { print "ERR " m; exit 1 }
    function hexv(ch) { return index("0123456789abcdef", ch) - 1 }
    BEGIN {
      split("CON PRN AUX NUL CLOCK$ COM1 COM2 COM3 COM4 COM5 COM6 COM7 COM8 COM9 LPT1 LPT2 LPT3 LPT4 LPT5 LPT6 LPT7 LPT8 LPT9 CONIN$ CONOUT$", r, " ")
      for (i in r) reserved[r[i]] = 1
    }
    $1 == "E" {
      idx = $2; method = $4; csize = $6; usize = $7; mode = $9; dos = $10; hex = $13
      if (length(hex) % 2 != 0) err("an entry name has an odd byte count")
      len = length(hex) / 2
      if (len > maxname) err("an entry name is longer than " maxname " bytes")
      totalname += len
      if (totalname > maxnamebytes) err("the archive names exceed the total name byte bound")
      s = ""; bad = 0
      for (i = 1; i <= length(hex); i += 2) {
        c = hexv(substr(hex, i, 1)) * 16 + hexv(substr(hex, i + 1, 1))
        if (c < 32 || c > 126) { bad = 1; c = 63 }
        else if (c == 34 || c == 42 || c == 60 || c == 62 || c == 63 || c == 91 || c == 92 || c == 93 || c == 124)
          bad = 1
        s = s sprintf("%c", c)
      }
      if (bad) err("an entry name has a byte outside the safe printable ASCII set")
      if (len == 0) err("an entry name is empty")
      if (substr(s, 1, 1) == "/") err("an entry name is absolute")
      isdir = (substr(s, len, 1) == "/")
      body = isdir ? substr(s, 1, len - 1) : s
      if (body == "") err("an entry name has no path")
      np = split(body, part, "/")
      if (np > maxcomp) err("an entry name has more than " maxcomp " path components")
      for (i = 1; i <= np; i++) {
        if (part[i] == "") err("an entry name has an empty path component")
        if (part[i] == "." || part[i] == "..") err("an entry name has a dot or parent path component")
        if (part[i] ~ /^ / || part[i] ~ / $/) err("an entry name has a component with a leading or trailing space")
        if (part[i] ~ /\.$/) err("an entry name has a component ending with a dot")
        if (index(part[i], ":") > 0) err("an entry name has a colon or drive letter")
        if (substr(part[i], 1, 1) == "-") err("an entry name component starts with a hyphen")
        base = part[i]
        sub(/\..*$/, "", base)
        base = toupper(base)
        if (base in reserved) err("an entry name uses a Windows reserved device name")
      }
      # Every path prefix must have one spelling, and the prefix bookkeeping
      # is capped so a hostile name cannot grow the map without bound.
      pre = ""
      for (i = 1; i <= np; i++) {
        pre = (i == 1) ? part[1] : pre "/" part[i]
        totalprefix++
        totalprefixbytes += length(pre)
        if (totalprefix > maxprefix) err("the archive path prefixes exceed the count bound")
        if (totalprefixbytes > maxprefixbytes) err("the archive path prefixes exceed the byte bound")
        pk = tolower(pre)
        if (pk in spell) {
          if (spell[pk] != pre) caseclash = 1
        } else {
          spell[pk] = pre
        }
      }
      key = tolower(s)
      if (s in exact) err("two entry names are identical")
      exact[s] = 1
      if (key in dirflag) {
        if (dirflag[key] != isdir) kindclash = 1
      } else {
        dirflag[key] = isdir
      }
      dirbody[key] = body
      if (!isdir) files[key] = 1
      type = int(mode / 4096)
      if (type == 4) mdir = 1
      else if (type == 8) mdir = 0
      else err("an entry is a special file type")
      if (mdir != isdir) err("an entry name and its file type disagree")
      if (int(mode / 512) % 8 != 0) err("an entry has setuid, setgid, or sticky bits")
      if ((int(dos / 16) % 2) == 1 && !isdir) err("the DOS directory bit disagrees with the entry")
      if (isdir && (csize != 0 || usize != 0)) err("a directory entry has a nonzero size")
      printf "V\t%d\t%s\t%d\t%d\t%d\t%d\n", idx, s, isdir, usize, mode, method
    }
    END {
      for (k in dirflag) {
        b = dirflag[k] ? k : dirbody[k]
        if (b == "") continue
        np = split(b, part, "/")
        pre = ""
        for (i = 1; i < np; i++) {
          pre = (i == 1) ? part[1] : pre "/" part[i]
          if (tolower(pre) in files) kindclash = 1
        }
      }
      if (caseclash) err("two entry names differ only in case")
      if (kindclash) err("an entry name is both a file and a directory")
    }' "$zn_meta"
}

# ---------------------------------------------------------------------------
# Archive helpers
# ---------------------------------------------------------------------------

# read_zip_plist ZIP ENTRY OUT USIZE CRC: stream one entry into OUT, at most
# max_plist_bytes. ENTRY is a validated exact name with no glob characters.
# The output must match the stored uncompressed size and CRC.
read_zip_plist() {
  rp_zip=$1; rp_entry=$2; rp_out=$3; rp_usize=$4; rp_crc=$5
  unzip -p "$rp_zip" "$rp_entry" </dev/null 2>/dev/null |
    head -c $((max_plist_bytes + 1)) > "$rp_out" || true
  rp_size=$(wc -c < "$rp_out" | tr -d ' ')
  [ "$rp_size" -gt 0 ] || return 1
  [ "$rp_size" -le "$max_plist_bytes" ] || return 1
  [ "$rp_size" -eq "$rp_usize" ] || return 1
  rp_got=$(crc32_file "$rp_out") || rp_got=""
  is_uint "$rp_got" || return 1
  is_uint "$rp_usize" || return 1
  is_uint "$rp_crc" || return 1
  [ "$rp_got" -eq "$rp_crc" ]
}

# check_bundle_version LABEL FILE
# Read CFBundleShortVersionString from FILE and compare it.
check_bundle_version() {
  cb_label=$1; cb_file=$2
  cb_short=$(plist_read "$cb_file" CFBundleShortVersionString || true)
  case "$cb_short" in
    "OK "*) cb_short=${cb_short#OK } ;;
    "ERR "*)
      cb_reason=$(printf "%s" "${cb_short#ERR }" | tr -c "A-Za-z0-9 ._()<>/-" "?" | head -c 120)
      fail "$cb_label: cannot read CFBundleShortVersionString from the plist: $cb_reason"
      return 0
      ;;
    *)
      fail "$cb_label: cannot read CFBundleShortVersionString from the plist"
      return 0
      ;;
  esac
  cb_build=$(plist_read "$cb_file" CFBundleVersion || true)
  case "$cb_build" in
    "OK "*) cb_build=${cb_build#OK } ;;
    *) cb_build="" ;;
  esac
  if [ "$cb_short" = "$expected" ]; then
    pass "$cb_label: CFBundleShortVersionString is $expected (CFBundleVersion $(printable "${cb_build:-missing}"))"
  else
    fail "$cb_label: CFBundleShortVersionString is $(printable "$cb_short"), expected $expected"
  fi
  return 0
}

# check_bundle_archive KIND PATH LABEL
# KIND is ipa or mac. Always returns 0 so that a failed archive never stops
# the run before the summary.
check_bundle_archive() {
  ba_kind=$1; ba_path=$2; ba_label=$3
  case "$ba_path" in
    /*) ;;
    *) ba_path="./$ba_path" ;;
  esac
  if [ -L "$ba_path" ] || [ ! -f "$ba_path" ]; then
    fail "$ba_label: not a regular file"
    return 0
  fi
  if ! command -v unzip >/dev/null 2>&1; then
    fail "$ba_label: unzip is unavailable"
    return 0
  fi
  if ! command -v gzip >/dev/null 2>&1; then
    fail "$ba_label: gzip is unavailable"
    return 0
  fi
  ba_meta="$work/meta.$$"
  ba_names="$work/names.$$"
  ba_estatus=0
  ba_eocd=$(zip_eocd "$ba_path") || ba_estatus=$?
  case "$ba_eocd" in
    ERR\ *)
      fail "$ba_label: ${ba_eocd#ERR }"
      rm -f "$ba_meta" "$ba_names"
      return 0
      ;;
    EOCD\ *)
      if [ "$ba_estatus" -ne 0 ]; then
        fail "$ba_label: the archive end-record reader failed"
        rm -f "$ba_meta" "$ba_names"
        return 0
      fi
      set -- $ba_eocd
      ba_entries=$2; ba_cdsize=$3; ba_cdoff=$4
      ;;
    *)
      fail "$ba_label: cannot read the archive end record"
      rm -f "$ba_meta" "$ba_names"
      return 0
      ;;
  esac
  ba_cstatus=0
  zip_cd "$ba_path" "$ba_cdoff" "$ba_cdsize" "$ba_entries" > "$ba_meta" || ba_cstatus=$?
  ba_err=$(grep '^ERR' "$ba_meta" 2>/dev/null | head -n 1 || true)
  if [ -n "$ba_err" ]; then
    fail "$ba_label: ${ba_err#ERR }"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  if [ "$ba_cstatus" -ne 0 ]; then
    fail "$ba_label: the central directory reader failed"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  ba_lstatus=0
  ba_local=$(zip_check_local "$ba_path" "$ba_meta" "$ba_cdoff") || ba_lstatus=$?
  if [ -n "$ba_local" ]; then
    fail "$ba_label: ${ba_local#ERR }"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  if [ "$ba_lstatus" -ne 0 ]; then
    fail "$ba_label: the local header verifier failed without a reason"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  ba_dstatus=0
  ba_data=$(zip_check_data "$ba_path" "$ba_meta") || ba_dstatus=$?
  case "$ba_data" in
    '')
      if [ "$ba_dstatus" -ne 0 ]; then
        fail "$ba_label: the payload verifier failed without a reason"
        rm -f "$ba_meta" "$ba_names"
        return 0
      fi
      ;;
    ERR\ *)
      ba_dreason=$(printf '%s' "${ba_data#ERR }" | tr -c 'A-Za-z0-9 ._()/<>,:-' '?' | head -c 160)
      [ -n "$ba_dreason" ] || ba_dreason="the payload verifier failed without a reason"
      fail "$ba_label: $ba_dreason"
      rm -f "$ba_meta" "$ba_names"
      return 0
      ;;
    *)
      fail "$ba_label: the payload verifier did not answer"
      rm -f "$ba_meta" "$ba_names"
      return 0
      ;;
  esac
  ba_nstatus=0
  zip_names "$ba_meta" > "$ba_names" || ba_nstatus=$?
  ba_nameerr=$(grep '^ERR' "$ba_names" 2>/dev/null | head -n 1 || true)
  if [ -n "$ba_nameerr" ]; then
    fail "$ba_label: ${ba_nameerr#ERR }"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  if [ "$ba_nstatus" -ne 0 ]; then
    fail "$ba_label: the entry name reader failed"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  ba_appnames=$("$awk_bin" -F"$(printf '\t')" -v kind="$ba_kind" '
    $1 == "V" {
      n = $3
      if (kind == "ipa") {
        if (n ~ /^Payload\/[^\/]+\.app\//) {
          s = substr(n, 9); sub(/\/.*/, "", s); print s
        }
      } else {
        if (n ~ /^[^\/]+\.app\//) {
          s = n; sub(/\/.*/, "", s); print s
        }
      }
    }' "$ba_names" | sort -u) || ba_appnames=""
  ba_napps=$(printf '%s\n' "$ba_appnames" | grep -c . || true)
  if [ "$ba_napps" -ne 1 ]; then
    fail "$ba_label: expected exactly one app bundle, found $ba_napps"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  ba_app=$ba_appnames
  if [ "$ba_kind" = ipa ]; then
    ba_plist="Payload/$ba_app/Info.plist"
  else
    ba_plist="$ba_app/Contents/Info.plist"
  fi
  ba_plist_info=$("$awk_bin" -F"$(printf '\t')" -v want="$ba_plist" \
    '$1 == "V" && $3 == want { print $2 "\t" $5 "\t" $6 "\t" $7 }' "$ba_names") || ba_plist_info=""
  ba_plist_idx=${ba_plist_info%%	*}
  if [ -z "$ba_plist_idx" ] || [ "$ba_plist_info" = "$ba_plist_idx" ]; then
    fail "$ba_label: expected exactly one top-level bundle Info.plist at $ba_plist"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  ba_plist_usize=$(printf '%s\n' "$ba_plist_info" | cut -f2) || ba_plist_usize=""
  ba_plist_crc=$("$awk_bin" -F'|' -v i="$ba_plist_idx" \
    '$1 == "E" && $2 == i { print $5 }' "$ba_meta" || true)
  if ! is_uint "$ba_plist_idx" || ! is_uint "$ba_plist_usize" || ! is_uint "$ba_plist_crc"; then
    fail "$ba_label: the Info.plist metadata is malformed"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  if [ "$ba_plist_usize" -le 0 ] || [ "$ba_plist_usize" -gt "$max_plist_bytes" ]; then
    fail "$ba_label: the Info.plist size is empty or larger than $max_plist_bytes bytes"
    rm -f "$ba_meta" "$ba_names"
    return 0
  fi
  if [ "$ba_kind" = mac ]; then
    ba_engine="$ba_app/Contents/Resources/bin/hotspotshade"
    ba_engine_info=$("$awk_bin" -F"$(printf '\t')" -v want="$ba_engine" \
      '$1 == "V" && $3 == want { print $2 "\t" $5 }' "$ba_names") || ba_engine_info=""
    if [ -z "$ba_engine_info" ]; then
      fail "$ba_label: the bundled engine Contents/Resources/bin/hotspotshade is missing"
      rm -f "$ba_meta" "$ba_names"
      return 0
    fi
    ba_engine_usize=$(printf '%s\n' "$ba_engine_info" | cut -f2) || ba_engine_usize=""
    if ! is_uint "$ba_engine_usize"; then
      fail "$ba_label: the bundled engine metadata is malformed"
      rm -f "$ba_meta" "$ba_names"
      return 0
    fi
    ba_engine_head="$work/engine.$$"
    if ! unzip -p "$ba_path" "$ba_engine" </dev/null 2>/dev/null > "$ba_engine_head" ||
       [ "$(wc -c < "$ba_engine_head" | tr -d ' ')" -ne "$ba_engine_usize" ]; then
      fail "$ba_label: cannot read the complete bundled engine"
      rm -f "$ba_engine_head" "$ba_meta" "$ba_names"
      return 0
    fi
    if ! macho_check_file "$ba_engine_head" \
      "$ba_label: the bundled engine"; then
      rm -f "$ba_engine_head" "$ba_meta" "$ba_names"
      return 0
    fi
    rm -f "$ba_engine_head"
    unver "$ba_label: the bundled engine Contents/Resources/bin/hotspotshade has an arm64 Mach-O executable header and structurally bounded load commands but carries no version field this check can read; its version is not established"
  fi
  ba_tmp="$work/plist.$$"
  if ! read_zip_plist "$ba_path" "$ba_plist" "$ba_tmp" "$ba_plist_usize" "$ba_plist_crc"; then
    fail "$ba_label: the Info.plist is empty, unreadable, larger than $max_plist_bytes bytes, or does not match its stored size and CRC"
    rm -f "$ba_tmp" "$ba_meta" "$ba_names"
    return 0
  fi
  check_bundle_version "$ba_label" "$ba_tmp"
  rm -f "$ba_tmp" "$ba_meta" "$ba_names"
  return 0
}

# ---------------------------------------------------------------------------
# Per-artifact checks
# ---------------------------------------------------------------------------

check_ipa() {
  check_bundle_archive ipa "$1" "$2"
}

check_mac_zip() {
  check_bundle_archive mac "$1" "$2"
}

check_mac_binary() {
  # check_mac_binary PATH LABEL
  mb_path=$1
  case "$mb_path" in
    /*) ;;
    *) mb_path="./$mb_path" ;;
  esac
  if [ -L "$mb_path" ] || [ ! -f "$mb_path" ]; then
    fail "$2: not a regular file"
    return 0
  fi
  if ! macho_check_file "$mb_path" "$2"; then
    return 0
  fi
  unver "$2: an arm64 Mach-O executable with structurally bounded load commands carries no trusted version field, and this check does not run it; embedded text that holds the number comes from web assets and is not the Cargo version. Expected $expected is not established"
  return 0
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if [ -n "$artifacts" ]; then
  if [ ! -d "$artifacts" ]; then
    fail "artifact directory is missing: $(label_path "$artifacts")"
  else
    ipa="$artifacts/HotspotShade-iOS-unsigned.ipa"
    mac_zip="$artifacts/HotspotShade-unsigned.zip"
    mac_binary="$artifacts/hotspotshade-macos-arm64.bin"
    for required in "$ipa" "$mac_zip" "$mac_binary"; do
      if [ -L "$required" ] || [ ! -f "$required" ]; then
        fail "the release set is missing a regular file: $(label "${required##*/}")"
      fi
    done
  fi
fi

# In --artifacts mode a missing file already failed above; do not report it twice.
usable() {
  [ -n "$1" ] || return 1
  [ -z "$artifacts" ] || { [ -f "$1" ] && [ ! -L "$1" ]; }
}
# Every check runs even after an earlier one failed, so the summary is complete.
if usable "$ipa"; then check_ipa "$ipa" "$(label "${ipa##*/}")" || true; fi
if usable "$mac_zip"; then check_mac_zip "$mac_zip" "$(label "${mac_zip##*/}")" || true; fi
if usable "$mac_binary"; then check_mac_binary "$mac_binary" "$(label "${mac_binary##*/}")" || true; fi

echo
echo "Summary: $passes passed, $unverified unverified, $failures failed"
if [ "$failures" -gt 0 ]; then
  echo "The artifact version check failed."
  exit 1
fi
if [ "$unverified" -gt 0 ]; then
  echo "Some artifact versions are not established by this check. Read every UNVERIFIED line."
  if [ "$allow_unverified" -eq 1 ]; then
    echo "The artifact version check passed with unverified items; this is not a verified release."
    exit 0
  fi
  exit 3
fi
echo "The artifact version check passed."
exit 0
