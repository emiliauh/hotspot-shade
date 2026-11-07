#!/bin/sh
# Read the version record that the macOS engine carries in its Mach-O file.
#
# rust/src/version.rs declares one 64-byte record in the __TEXT,__hsver
# section. This reader finds that section in the Mach-O load commands, proves
# that the section is a regular, 64-byte, file-backed range in __TEXT, reads
# the record, and prints the version. It reads the artifact bytes only. It
# does not run the artifact, read a sidecar file, use the network, a device,
# a route, or a credential.
#
# Record layout (HSSHVER1, format 1):
#   bytes  0..7    "HSSHVER1"
#   byte   8       1
#   byte   9       version length, 1..32
#   bytes 10..      version text, N.N.N with decimal digits
#   rest           zero padding
#
# The reader is stricter than the linker. It requires:
#   - a little-endian 64-bit arm64 MH_EXECUTE header;
#   - a load-command area that is aligned, consistent, and at most 1 MiB;
#   - exactly one __TEXT segment and exactly one __hsver section in it;
#   - the section name and its segment name to fill their 16-byte fields
#     exactly, with zero padding;
#   - S_REGULAR type, a size of exactly 64 bytes;
#   - bounded file extents for every segment and file-backed section;
#   - file and virtual containment and consistent mapping for __hsver;
#   - no other segment or file-backed section overlapping its bytes;
#   - a section offset after the header and load commands;
#   - the record magic, format, length, grammar, and zero padding.
#
# Usage: scripts/macho_version.sh FILE
#
# On success the only stdout is the version and the exit status is 0. On any
# malformed input or a read/parse failure the script normally prints a fixed
# message to stderr, prints nothing to stdout, and exits 1. The shell or OS may
# also report redirection, signal, or cleanup errors. Usage, missing tools, and
# temporary-directory errors exit 2 with a specific diagnostic. This reader is metadata only: it
# does not prove source, signature, or runnability, and the release gate that
# would consume it is still closed.
#
# Parsing uses a private snapshot, not repeated reads of the input pathname.
# The input may change while copied, and POSIX shell cannot guarantee nofollow
# or exclude mutation by the same user. The output identifies that snapshot,
# not a later pathname read. A consumer must arrange immutable input and bind
# all audit and release steps to the same controlled bytes. A separate full
# audit must validate Mach-O framing and all other required properties.
#
# Programs: POSIX sh, dd, od, tr, awk, wc, mktemp, rm. Awk must support
# POSIX awk semantics and exact integers through 2^53-1 (typically IEEE 754
# double). Set HS_AWK to an executable path to test another implementation.
set -eu

# Byte-wise matching. A hostile name must not change a comparison through the
# locale.
LC_ALL=C
export LC_ALL

# Bounds. A release engine is a few megabytes. Anything far larger is refused
# before a byte is parsed.
max_file_bytes=1073741824
max_load_command_bytes=1048576
max_load_commands=4096
max_sections=4096
# Mach-O stores 64-bit fields. Above 2^53 - 1 an awk number is not exact, so a
# value there could pass a bound check it should fail.
max_exact_integer=9007199254740991

fail() {
  printf 'macho_version: the file has no valid version record\n' >&2
  exit 1
}

usage() {
  printf 'usage: macho_version.sh FILE\n' >&2
  exit 2
}

awk_bin=${HS_AWK:-awk}
if ! command -v "$awk_bin" >/dev/null 2>&1; then
  printf 'macho_version: awk is unavailable\n' >&2
  exit 2
fi
for program in dd od tr wc mktemp rm; do
  if ! command -v "$program" >/dev/null 2>&1; then
    printf 'macho_version: %s is unavailable\n' "$program" >&2
    exit 2
  fi
done

[ "$#" -eq 1 ] || usage
file=$1
case "$file" in
  ''|-*) usage ;;
esac
if [ -h "$file" ]; then
  fail
fi
if [ ! -f "$file" ] || [ ! -r "$file" ]; then
  fail
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/hs-macho.XXXXXXXX" 2>/dev/null) || {
  printf 'macho_version: cannot create a work directory\n' >&2
  exit 2
}
case "$work" in
  /*) ;;
  *) work="./$work" ;;
esac
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# read_bytes FILE OFFSET COUNT OUTFILE
# Write the decimal value of each byte on its own line. The od, tr, and awk
# callers check every status; a short read leaves fewer lines and the byte
# count check refuses it.
read_bytes() {
  rb_file=$1
  rb_offset=$2
  rb_count=$3
  rb_out=$4
  od -An -v -tu1 -j "$rb_offset" -N "$rb_count" "$rb_file" \
    > "$work/raw" 2>/dev/null || return 1
  tr -s ' \n' '\n' < "$work/raw" > "$rb_out" 2>/dev/null || return 1
  return 0
}

# Copy at most the size limit plus one block with one input open. The private
# directory prevents access by other users, subject to the host mktemp and
# filesystem semantics. It does not protect against the same user.
umask 077
if ! dd bs=1048576 count=1025 < "$file" > "$work/snapshot" 2>/dev/null; then
  fail
fi
file=$work/snapshot

# ---------------------------------------------------------------------------
# File size
# ---------------------------------------------------------------------------

size=$(wc -c < "$file" 2>/dev/null) || fail
size=$(printf '%s' "$size" | tr -d ' \n' 2>/dev/null) || fail
case "$size" in
  ''|*[!0-9]*) fail ;;
esac
[ "$size" -ge 32 ] || fail
[ "$size" -le "$max_file_bytes" ] || fail

# ---------------------------------------------------------------------------
# Mach-O header
# ---------------------------------------------------------------------------

read_bytes "$file" 0 32 "$work/header" || fail

if ! header=$( "$awk_bin" -v full="$size" \
    -v maxcmds="$max_load_commands" -v maxbytes="$max_load_command_bytes" '
  { if (NF) b[n++] = $1 + 0 }
  function u32(p) {
    return b[p] + 256 * b[p+1] + 65536 * b[p+2] + 16777216 * b[p+3]
  }
  END {
    if (n != 32) exit 1
    # MH_MAGIC_64, CPU_TYPE_ARM64, MH_EXECUTE.
    if (u32(0) != 4277009103) exit 1
    if (u32(4) != 16777228) exit 1
    subt = u32(8)
    if (subt != 0 && subt != 1 && subt != 2) exit 1
    if (u32(12) != 2) exit 1
    nc = u32(16)
    sc = u32(20)
    if (nc < 1 || nc > maxcmds) exit 1
    if (sc % 8 != 0) exit 1
    if (sc < 8 * nc) exit 1
    if (sc > maxbytes) exit 1
    if (32 + sc > full) exit 1
    print sc " " nc
  }
' "$work/header" 2>/dev/null); then
  fail
fi

case "$header" in
  *' '*) ;;
  *) fail ;;
esac
cmdsize=${header% *}
ncmds=${header#* }
case "$cmdsize$ncmds" in
  ''|*[!0-9]*) fail ;;
esac
[ "$cmdsize" -ge 8 ] || fail
[ "$cmdsize" -le "$max_load_command_bytes" ] || fail
[ "$ncmds" -ge 1 ] || fail
[ "$ncmds" -le "$max_load_commands" ] || fail

# ---------------------------------------------------------------------------
# Load commands and the __hsver section
# ---------------------------------------------------------------------------

read_bytes "$file" 32 "$cmdsize" "$work/commands" || fail

if ! section_offset=$( "$awk_bin" -v ncmds="$ncmds" -v cmdsize="$cmdsize" \
    -v full="$size" -v maxsections="$max_sections" \
    -v maxsafe="$max_exact_integer" '
  { if (NF) b[n++] = $1 + 0 }
  function u32(p) {
    return b[p] + 256 * b[p+1] + 65536 * b[p+2] + 16777216 * b[p+3]
  }
  function u64(p) {
    return u32(p) + 4294967296 * u32(p+4)
  }
  # The 16-byte name field must hold NAME followed by zero bytes.
  function exact(p, name,   k, c, len) {
    len = length(name)
    for (k = 0; k < 16; k++) {
      c = b[p+k]
      if (k < len) {
        if (c != ord[substr(name, k+1, 1)]) return 0
      } else if (c != 0) return 0
    }
    return 1
  }
  # The first bytes of the field spell NAME. The tail is checked separately,
  # so a lookalike name is refused rather than ignored or accepted.
  function starts(p, name,   k) {
    for (k = 1; k <= length(name); k++) {
      if (b[p+k-1] != ord[substr(name, k, 1)]) return 0
    }
    return 1
  }
  BEGIN {
    for (i = 32; i < 127; i++) ord[sprintf("%c", i)] = i
  }
  END {
    if (n != cmdsize) exit 1
    pos = 0
    total_sections = 0
    text_segments = 0
    found = 0
    for (j = 0; j < ncmds; j++) {
      if (pos + 8 > n) exit 1
      cmd = u32(pos)
      sz = u32(pos + 4)
      if (sz < 8 || sz % 8 != 0 || pos + sz > n) exit 1
      # A 32-bit segment command cannot appear in a 64-bit image.
      if (cmd == 1) exit 1
      if (cmd == 25) {
        if (sz < 72) exit 1
        nsects = u32(pos + 64)
        if (sz != 72 + 80 * nsects) exit 1
        total_sections += nsects
        if (total_sections > maxsections) exit 1
        seg_off = u64(pos + 40)
        seg_len = u64(pos + 48)
        seg_vm = u64(pos + 24)
        seg_vlen = u64(pos + 32)
        # Subtraction checks avoid rounding an overflowing sum.
        if (seg_off > maxsafe || seg_len > maxsafe || seg_off > full || seg_len > full - seg_off) exit 1
        if (seg_vm > maxsafe || seg_vlen > maxsafe || seg_vlen > maxsafe - seg_vm) exit 1
        is_text = exact(pos + 8, "__TEXT")
        if (is_text) text_segments++
        seg_count++
        segment_off[seg_count] = seg_off
        segment_len[seg_count] = seg_len
        for (k = 0; k < nsects; k++) {
          sp = pos + 72 + 80 * k
          off = u32(sp + 48)
          len = u64(sp + 40)
          flags = u32(sp + 64)
          type = flags % 256
          # S_ZEROFILL, S_GB_ZEROFILL and S_THREAD_LOCAL_ZEROFILL
          # have no file bytes. All other section types are file-backed.
          backed = type != 1 && type != 12 && type != 18
          if (len > maxsafe) exit 1
          if (backed && len > 0) {
            if (off > full || len > full - off) exit 1
            if (off < seg_off || off - seg_off > seg_len || len > seg_len - (off - seg_off)) exit 1
            section_count++
            section_off[section_count] = off
            section_len[section_count] = len
          }
          if (starts(sp, "__hsver")) {
            if (!is_text || !exact(sp, "__hsver") || !exact(sp + 16, "__TEXT")) exit 1
            found++
            if (found > 1) exit 1
            hs_offset = off
            hs_size = len
            hs_flags = flags
            hs_fileoff = seg_off
            hs_filesize = seg_len
            hs_vm = seg_vm
            hs_vlen = seg_vlen
            hs_addr = u64(sp + 32)
            hs_segment = seg_count
            hs_section = section_count
          }
        }
      }
      pos += sz
    }
    if (pos != n) exit 1
    if (text_segments != 1) exit 1
    if (found != 1) exit 1
    if (hs_flags % 256 != 0) exit 1
    if (hs_size != 64) exit 1
    if (hs_filesize <= 0) exit 1
    if (hs_fileoff > maxsafe || hs_filesize > maxsafe || hs_size > maxsafe) exit 1
    if (hs_fileoff + hs_filesize > full) exit 1
    if (hs_offset > maxsafe) exit 1
    # The record must sit after the header and load commands.
    if (hs_offset < 32 + cmdsize) exit 1
    if (hs_offset < hs_fileoff) exit 1
    if (hs_offset - hs_fileoff + hs_size > hs_filesize) exit 1
    if (hs_offset + hs_size > full) exit 1
    if (hs_addr > maxsafe || hs_addr < hs_vm) exit 1
    delta = hs_addr - hs_vm
    if (delta > hs_vlen || hs_size > hs_vlen - delta) exit 1
    if (delta != hs_offset - hs_fileoff) exit 1
    for (i = 1; i <= seg_count; i++) {
      if (i != hs_segment && segment_len[i] > 0 &&
          segment_off[i] < hs_offset + hs_size && hs_offset < segment_off[i] + segment_len[i]) exit 1
    }
    for (i = 1; i <= section_count; i++) {
      if (i != hs_section && section_off[i] < hs_offset + hs_size &&
          hs_offset < section_off[i] + section_len[i]) exit 1
    }
    print hs_offset
  }
' "$work/commands" 2>/dev/null); then
  fail
fi

case "$section_offset" in
  ''|*[!0-9]*) fail ;;
esac
[ "$section_offset" -le $((size - 64)) ] || fail

# ---------------------------------------------------------------------------
# The 64-byte record
# ---------------------------------------------------------------------------

read_bytes "$file" "$section_offset" 64 "$work/record" || fail

if ! version=$( "$awk_bin" '
  { if (NF) b[n++] = $1 + 0 }
  BEGIN {
    for (i = 32; i < 127; i++) ord[sprintf("%c", i)] = i
  }
  END {
    if (n != 64) exit 1
    magic = "HSSHVER1"
    for (k = 0; k < 8; k++) {
      if (b[k] != ord[substr(magic, k+1, 1)]) exit 1
    }
    if (b[8] != 1) exit 1
    len = b[9]
    if (len < 1 || len > 32) exit 1
    dots = 0
    previous_dot = 1
    text = ""
    for (k = 0; k < len; k++) {
      c = b[10+k]
      if (c == 46) {
        if (previous_dot) exit 1
        dots++
        previous_dot = 1
      } else if (c >= 48 && c <= 57) {
        previous_dot = 0
      } else {
        exit 1
      }
      text = text sprintf("%c", c)
    }
    if (dots != 2 || previous_dot) exit 1
    for (k = 10 + len; k < 64; k++) {
      if (b[k] != 0) exit 1
    }
    print text
  }
' "$work/record" 2>/dev/null); then
  fail
fi

# Defence in depth. The awk program already proved the grammar; the shell
# repeats the cheap checks and refuses more than one line or any other byte.
case "$version" in
  ''|*[!0-9.]*|.*|*.|*..*) fail ;;
  *'
'*) fail ;;
esac
[ "${#version}" -ge 5 ] || fail
[ "${#version}" -le 32 ] || fail

printf '%s\n' "$version"
