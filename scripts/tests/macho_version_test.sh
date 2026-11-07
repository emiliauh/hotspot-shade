#!/usr/bin/env bash
# Hermetic adversarial tests for scripts/macho_version.sh.
#
# Every fixture is built here from literal bytes. No fixture is downloaded,
# extracted, or produced by a linker, and nothing in this test runs an
# artifact. The record spec lives in rust/src/version.rs: HSSHVER1, format 1,
# version length 1..32, N.N.N, zero padding.
#
# The test covers the arm64 MH_EXECUTE header, the bounded load-command area,
# LC_SEGMENT_64 section records, the __TEXT,__hsver placement rules, and the
# 64-byte record itself. It also runs the real macOS release binary when that
# file is present, without requiring it.
#
# The GNU container leg runs the same script in debian:bookworm-slim with
# --network none. It is skipped when docker or the image is unavailable, and
# when the script already runs inside the container.
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
# HS_MACHO_READER lets a reviewer point the suite at a mutated copy of the
# reader to prove that a check is load bearing. It is not used in CI.
reader=${HS_MACHO_READER:-$repo_dir/scripts/macho_version.sh}
work=$(mktemp -d "${TMPDIR:-/tmp}/hs-macho-test.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
LC_ALL=C
export LC_ALL

fixed_error='macho_version: the file has no valid version record'

failures=0
checks=0
status=0
out="$work/stdout"
err="$work/stderr"

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

# run ARGS... -> sets status, out, err
run() {
  status=0
  : > "$out"
  : > "$err"
  sh "$reader" "$@" > "$out" 2> "$err" || status=$?
  checks=$((checks + 1))
}

# check_ok FILE EXPECTED LABEL
check_ok() {
  run "$1"
  if [ "$status" -ne 0 ]; then
    fail "$3 (expected exit 0, got $status; stderr: $(head -c 200 "$err" | tr '\n' ' '))"
    return
  fi
  if [ -s "$err" ]; then
    fail "$3 (stderr is not empty)"
  fi
  local lines
  lines=$(wc -l < "$out" | tr -d ' ')
  if [ "$lines" -ne 1 ]; then
    fail "$3 (stdout has $lines lines)"
    return
  fi
  local got
  got=$(cat "$out")
  if [ "$got" != "$2" ]; then
    fail "$3 (expected '$2', got '$got')"
  fi
  local bytes
  bytes=$(wc -c < "$out" | tr -d ' ')
  if [ "$bytes" -ne $(( ${#2} + 1 )) ]; then
    fail "$3 (stdout is $bytes bytes, expected $((${#2} + 1)))"
  fi
  case "$got" in
    *"$(printf '\033')"*) fail "$3 (an escape reached stdout)" ;;
  esac
}

# check_fail FILE LABEL
check_fail() {
  run "$1"
  if [ "$status" -ne 1 ]; then
    fail "$2 (expected exit 1, got $status)"
    return
  fi
  if [ -s "$out" ]; then
    fail "$2 (stdout is not empty)"
  fi
  local text
  text=$(cat "$err")
  if [ "$text" != "$fixed_error" ]; then
    fail "$2 (unexpected stderr: $text)"
  fi
  local bytes
  bytes=$(wc -c < "$err" | tr -d ' ')
  if [ "$bytes" -ne $(( ${#fixed_error} + 1 )) ]; then
    fail "$2 (stderr is $bytes bytes, expected $((${#fixed_error} + 1)))"
  fi
  case "$text" in
    *"$(printf '\033')"*) fail "$2 (an escape reached stderr)" ;;
  esac
}

# ---------------------------------------------------------------------------
# Byte writer
# ---------------------------------------------------------------------------

blob=()
blob_reset() { blob=(); }
b_u8() {
  local piece
  printf -v piece '\\%03o' "$(( $1 & 255 ))"
  blob+=("$piece")
}
b_u16() { b_u8 "$(( $1 & 255 ))"; b_u8 "$(( ($1 >> 8) & 255 ))"; }
b_u32() { b_u16 "$(( $1 & 65535 ))"; b_u16 "$(( ($1 >> 16) & 65535 ))"; }
b_u64() { b_u32 "$(( $1 & 4294967295 ))"; b_u32 "$(( ($1 >> 32) & 4294967295 ))"; }
b_name16() {
  local name=$1 i code
  for ((i = 0; i < 16; i++)); do
    if [ "$i" -lt "${#name}" ]; then
      printf -v code '%d' "'${name:i:1}"
      b_u8 "$code"
    else
      b_u8 0
    fi
  done
}
b_flush() {
  if [ "${#blob[@]}" -gt 0 ]; then
    printf '%b' "${blob[@]}"
  fi
}

esc_ascii() {
  local text=$1 out="" i code piece
  for ((i = 0; i < ${#text}; i++)); do
    printf -v code '%d' "'${text:i:1}"
    printf -v piece '\\%03o' "$code"
    out+=$piece
  done
  printf '%s' "$out"
}
esc_u32() {
  printf '\\%03o\\%03o\\%03o\\%03o' \
    "$(( $1 & 255 ))" "$(( ($1 >> 8) & 255 ))" \
    "$(( ($1 >> 16) & 255 ))" "$(( ($1 >> 24) & 255 ))"
}
esc_u64() {
  printf '%s%s' "$(esc_u32 "$(( $1 & 4294967295 ))")" \
    "$(esc_u32 "$(( ($1 >> 32) & 4294967295 ))")"
}
zeros_esc() {
  local spaces
  printf -v spaces '%*s' "$1" ''
  printf '%s' "${spaces// /\\000}"
}

# write_record FILE OFFSET: the canonical record for version 0.1.0.
write_record() {
  local esc
  esc=$(esc_ascii 'HSSHVER1')'\001\005'$(esc_ascii '0.1.0')"$(zeros_esc 54)"
  printf '%b' "$esc" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

# build_engine FILE S1 S2 SIZE
# One little-endian 64-bit arm64 MH_EXECUTE with a __TEXT segment holding S1
# sections and, when S2 is zero or more, a __DATA segment holding S2 sections.
# Section 0 in each segment is named __hsver and points at a record. Section 1
# in __TEXT is a second __hsver. Later sections have empty names.
build_engine() {
  local file=$1 s1=$2 s2=$3 size=$4
  local ncmds=1 sizeofcmds i named1
  local cmd1=$((72 + 80 * s1))
  local cmd2=0
  if [ "$s2" -ge 0 ]; then
    ncmds=2
    cmd2=$((72 + 80 * s2))
    sizeofcmds=$((cmd1 + cmd2))
  else
    sizeofcmds=$cmd1
  fi
  # A very large section count is only used for the cap test. Emit one named
  # section and leave the rest unnamed, so the cap is the only failure.
  named1=$s1
  if [ "$s1" -gt 2 ]; then
    named1=1
  fi

  blob_reset
  # Mach-O header.
  b_u32 4277009103      # MH_MAGIC_64
  b_u32 16777228        # CPU_TYPE_ARM64
  b_u32 0               # CPU_SUBTYPE_ARM64_ALL
  b_u32 2               # MH_EXECUTE
  b_u32 "$ncmds"
  b_u32 "$sizeofcmds"
  b_u32 0
  b_u32 0

  # __TEXT.
  b_u32 25
  b_u32 "$cmd1"
  b_name16 __TEXT
  b_u64 4294967296
  b_u64 4096
  b_u64 0
  b_u64 "$([ "$s2" -ge 0 ] && printf 2048 || printf 4096)"
  b_u32 7
  b_u32 5
  b_u32 "$s1"
  b_u32 0
  for ((i = 0; i < named1; i++)); do
    b_name16 __hsver
    b_name16 __TEXT
    b_u64 $((4294967296 + 1024 + 64 * i))
    b_u64 64
    b_u32 $((1024 + 64 * i))
    b_u32 0
    b_u32 0
    b_u32 0
    b_u32 0
    b_u32 0
    b_u32 0
    b_u32 0
  done

  # Write the header and the first segment. A long run of unnamed sections is
  # written as raw zeros: building a multi-hundred-kilobyte escape string in
  # the shell is slow on bash 3.2.
  b_flush > "$file"
  if [ "$s1" -gt "$named1" ]; then
    head -c $((80 * (s1 - named1))) /dev/zero >> "$file"
  fi

  if [ "$s2" -ge 0 ]; then
    blob_reset
    # __DATA.
    b_u32 25
    b_u32 "$cmd2"
    b_name16 __DATA
    b_u64 4294969344
    b_u64 1024
    b_u64 2048
    b_u64 1024
    b_u32 3
    b_u32 3
    b_u32 "$s2"
    b_u32 0
    for ((i = 0; i < s2 && i < 1; i++)); do
      b_name16 __hsver
      b_name16 __DATA
      b_u64 4294969344
      b_u64 64
      b_u32 2048
      b_u32 0
      b_u32 0
      b_u32 0
      b_u32 0
      b_u32 0
      b_u32 0
      b_u32 0
    done
    b_flush >> "$file"
    if [ "$s2" -gt 1 ]; then
      head -c $((80 * (s2 - 1))) /dev/zero >> "$file"
    fi
  fi

  local have
  have=$(wc -c < "$file" | tr -d ' ')
  if [ "$have" -lt "$size" ]; then
    head -c $((size - have)) /dev/zero >> "$file"
  fi
  if [ "$size" -ge 1088 ]; then
    write_record "$file" 1024
    write_record "$file" 1088
  fi
  if [ "$size" -ge 2112 ]; then
    write_record "$file" 2048
  fi
}

# Field patch helpers. Offsets are zero based.
patch_u8() {
  printf '%b' "$(printf '\\%03o' "$(( $3 & 255 ))")" |
    dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
patch_u32() {
  printf '%b' "$(esc_u32 "$3")" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
patch_u64() {
  printf '%b' "$(esc_u64 "$3")" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
patch_text() {
  printf '%s' "$3" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
zero_region() {
  dd if=/dev/zero of="$1" bs=1 seek="$2" count="$3" conv=notrunc 2>/dev/null
}

base="$work/base.bin"
build_engine "$base" 1 -1 4096

# Header field offsets.
O_MAGIC=0
O_CPUTYPE=4
O_SUBTYPE=8
O_FILETYPE=12
O_NCMDS=16
O_SIZEOFCMDS=20
# First LC_SEGMENT_64 at 32.
O_CMD=32
O_CMDSIZE=36
O_SEGNAME=40
O_SEG_FILEOFF=72
O_SEG_FILESIZE=80
O_NSECTS=96
# First section at 104.
O_SECTNAME=104
O_SECT_SEGNAME=120
O_SECT_SIZE=144
O_SECT_OFFSET=152
O_SECT_FLAGS=168
# Record at 1024.
O_RECORD=1024
O_RECORD_LEN=1033
O_RECORD_FORMAT=1032
O_RECORD_TEXT=1034

# ---------------------------------------------------------------------------
# Positive controls
# ---------------------------------------------------------------------------

check_ok "$base" 0.1.0 'the canonical fixture reads 0.1.0'

cp "$base" "$work/leading.bin"
patch_text "$work/leading.bin" "$O_RECORD_TEXT" '01.02.03'
patch_u8 "$work/leading.bin" "$O_RECORD_LEN" 8
check_ok "$work/leading.bin" 01.02.03 'leading zeros follow the digit grammar'

cp "$base" "$work/multidigit.bin"
patch_text "$work/multidigit.bin" "$O_RECORD_TEXT" '10.20.30'
patch_u8 "$work/multidigit.bin" "$O_RECORD_LEN" 8
check_ok "$work/multidigit.bin" 10.20.30 'multi-digit version parts are read'

cp "$base" "$work/maxlen.bin"
patch_text "$work/maxlen.bin" "$O_RECORD_TEXT" '1234567890123456789012345678.1.2'
patch_u8 "$work/maxlen.bin" "$O_RECORD_LEN" 32
check_ok "$work/maxlen.bin" 1234567890123456789012345678.1.2 'a 32-byte version is the limit'

# A second segment without sections is harmless.
build_engine "$work/extra-segment.bin" 1 0 4096
check_ok "$work/extra-segment.bin" 0.1.0 'a __DATA segment without sections is accepted'

# __hsver does not have to be the first section in __TEXT, and the record is
# read at the section offset rather than at a fixed place.
build_engine "$work/second-section.bin" 2 -1 4096
patch_text "$work/second-section.bin" "$O_SECTNAME" '__text'
patch_text "$work/second-section.bin" 1098 '2.3.4'
patch_u8 "$work/second-section.bin" 1097 5
check_ok "$work/second-section.bin" 2.3.4 '__hsver is found after another section'

# ---------------------------------------------------------------------------
# File shape and usage
# ---------------------------------------------------------------------------

head -c 16 "$base" > "$work/short.bin"
check_fail "$work/short.bin" 'a file shorter than the Mach-O header fails'

: > "$work/empty.bin"
check_fail "$work/empty.bin" 'an empty file fails'

check_fail "$work/does-not-exist.bin" 'a missing file fails'
check_fail "$work" 'a directory fails'

ln -sf "$base" "$work/link.bin"
check_fail "$work/link.bin" 'a symlink fails'

status=0
sh "$reader" > "$out" 2> "$err" || status=$?
checks=$((checks + 1))
[ "$status" -eq 2 ] || fail "no argument is a usage error (got $status)"
[ -s "$out" ] && fail 'the usage error wrote to stdout'

status=0
sh "$reader" "$base" "$base" > "$out" 2> "$err" || status=$?
checks=$((checks + 1))
[ "$status" -eq 2 ] || fail "two arguments are a usage error (got $status)"

status=0
sh "$reader" --help > "$out" 2> "$err" || status=$?
checks=$((checks + 1))
[ "$status" -eq 2 ] || fail "--help is not a version and exits 2 (got $status)"
[ -s "$out" ] && fail '--help wrote to stdout'

# The reader must never execute the artifact.
cat > "$work/script.bin" <<SCRIPT
#!/bin/sh
: > "$work/pwned"
exit 0
SCRIPT
chmod +x "$work/script.bin"
check_fail "$work/script.bin" 'a shell script is not a Mach-O file'
[ ! -e "$work/pwned" ] || fail 'the reader executed the artifact'

# A sidecar that names a version must not be trusted.
cp "$work/short.bin" "$work/sidecar.bin"
printf '9.9.9\n' > "$work/sidecar.bin.version"
printf '9.9.9\n' > "$work/version.txt"
check_fail "$work/sidecar.bin" 'a sidecar version file is not used'

# ---------------------------------------------------------------------------
# Mach-O header
# ---------------------------------------------------------------------------

patch_case() {
  # patch_case LABEL FUNCTION OFFSET VALUE
  local label=$1 fn=$2 off=$3 value=$4
  cp "$base" "$work/case.bin"
  "$fn" "$work/case.bin" "$off" "$value"
  check_fail "$work/case.bin" "$label"
}

patch_case 'a wrong Mach-O magic fails' patch_u32 "$O_MAGIC" 4277009102
patch_case 'a non-arm64 CPU type fails' patch_u32 "$O_CPUTYPE" 16777223
patch_case 'an unsupported arm64 subtype fails' patch_u32 "$O_SUBTYPE" 3
patch_case 'a non-executable file type fails' patch_u32 "$O_FILETYPE" 6
patch_case 'a zero load-command count fails' patch_u32 "$O_NCMDS" 0
patch_case 'a load-command count over the cap fails' patch_u32 "$O_NCMDS" 4097
patch_case 'load commands over 1 MiB fail' patch_u32 "$O_SIZEOFCMDS" 1048584
patch_case 'load commands past the file fail' patch_u32 "$O_SIZEOFCMDS" 4080
patch_case 'unaligned load commands fail' patch_u32 "$O_SIZEOFCMDS" 153
patch_case 'a load-command area shorter than its count fails' patch_u32 "$O_SIZEOFCMDS" 8
patch_case 'a sizeofcmds that does not match the commands fails' patch_u32 "$O_SIZEOFCMDS" 160

printf 'not a Mach-O file at all, just text bytes here' > "$work/text.bin"
check_fail "$work/text.bin" 'plain text fails'

# ---------------------------------------------------------------------------
# Load commands and section placement
# ---------------------------------------------------------------------------

patch_case 'a load command that is too large fails' patch_u32 "$O_CMDSIZE" 120
patch_case 'a zero load-command size fails' patch_u32 "$O_CMDSIZE" 0
patch_case 'an unaligned load-command size fails' patch_u32 "$O_CMDSIZE" 156
patch_case 'a 32-bit segment command in a 64-bit image fails' patch_u32 "$O_CMD" 1
patch_case 'a section count that disagrees with the command size fails' patch_u32 "$O_NSECTS" 2
patch_case 'a segment name with a nonzero tail fails' patch_u8 $((O_SEGNAME + 7)) 65
patch_case 'a section name with a nonzero tail fails' patch_u8 $((O_SECTNAME + 7)) 120
patch_case 'a section segment name with a nonzero tail fails' patch_u8 $((O_SECT_SEGNAME + 7)) 65
patch_case 'a section in a different segment name fails' patch_text "$O_SECT_SEGNAME" '__DATA'
patch_case 'a section size that is not 64 bytes fails' patch_u64 "$O_SECT_SIZE" 128
patch_case 'a non-regular section type fails' patch_u32 "$O_SECT_FLAGS" 1
patch_case 'a section inside the load commands fails' patch_u32 "$O_SECT_OFFSET" 40
patch_case 'a section past the end of the file fails' patch_u32 "$O_SECT_OFFSET" 4064
patch_case 'a section outside its segment extent fails' patch_u64 "$O_SEG_FILESIZE" 1024
patch_case 'a segment that is not file backed fails' patch_u64 "$O_SEG_FILESIZE" 0
patch_case 'a segment extent past the file fails' patch_u64 "$O_SEG_FILESIZE" 8192
patch_case 'an inexact 64-bit segment offset fails' patch_u64 "$O_SEG_FILEOFF" 9223372036854775807

cp "$base" "$work/outside.bin"
patch_u64 "$work/outside.bin" "$O_SEG_FILEOFF" 2048
patch_u64 "$work/outside.bin" "$O_SEG_FILESIZE" 1024
check_fail "$work/outside.bin" 'a section before the segment file offset fails'

# Independent controls for extent and mapping checks. The extra segment starts
# exactly at the end of __TEXT and carries no sections.
cp "$work/extra-segment.bin" "$work/segment-overlap.bin"
patch_u64 "$work/segment-overlap.bin" 224 1080
check_fail "$work/segment-overlap.bin" 'another segment overlapping the record fails'
cp "$work/extra-segment.bin" "$work/bad-unrelated.bin"
patch_u64 "$work/bad-unrelated.bin" 224 4097
check_fail "$work/bad-unrelated.bin" 'an unrelated segment outside the file fails'

cp "$work/second-section.bin" "$work/section-overlap.bin"
# The first section is __text; the second is __hsver.
patch_u32 "$work/section-overlap.bin" 152 1057
check_fail "$work/section-overlap.bin" 'another file-backed section overlapping the record fails'
cp "$work/second-section.bin" "$work/bad-section.bin"
patch_u64 "$work/bad-section.bin" "$O_SEG_FILESIZE" 2048
patch_u32 "$work/bad-section.bin" 152 2050
check_fail "$work/bad-section.bin" 'an unrelated section inside the file but outside its segment fails'
for type in 1 12 18; do
  cp "$work/second-section.bin" "$work/zerofill.bin"
  patch_u32 "$work/zerofill.bin" 152 1088
  patch_u32 "$work/zerofill.bin" 168 "$type"
  check_ok "$work/zerofill.bin" 2.3.4 "zerofill type $type has no overlapping file bytes"
  cp "$base" "$work/zerofill-target.bin"
  patch_u32 "$work/zerofill-target.bin" "$O_SECT_FLAGS" "$type"
  check_fail "$work/zerofill-target.bin" "zerofill type $type cannot hold the version record"
done
patch_case 'a virtual address with a different file mapping fails' patch_u64 136 4294968321
patch_case 'a virtual section outside its segment fails' patch_u64 64 1050
patch_case 'a virtual address below its segment fails' patch_u64 136 4294967295
patch_case 'an overflowing segment virtual range fails' patch_u64 56 9007199254740991

# Two __hsver sections in __TEXT are ambiguous.
build_engine "$work/duplicate.bin" 2 -1 4096
check_fail "$work/duplicate.bin" 'a duplicate __hsver section fails'

# __hsver only under __DATA is not in __TEXT.
build_engine "$work/data.bin" 0 1 4096
check_fail "$work/data.bin" '__hsver outside __TEXT fails'

# A __TEXT segment with no __hsver section is missing the record.
build_engine "$work/nohsver.bin" 1 -1 4096
patch_text "$work/nohsver.bin" "$O_SECTNAME" '__text'
check_fail "$work/nohsver.bin" 'a missing __hsver section fails'

# Two segments named __TEXT are ambiguous.
build_engine "$work/twotext.bin" 1 1 4096
patch_text "$work/twotext.bin" 192 '__TEXT'
patch_text "$work/twotext.bin" 272 '__TEXT'
check_fail "$work/twotext.bin" 'two __TEXT segments fail'

# The same with no section in the second __TEXT segment: the segment name
# alone is ambiguous.
build_engine "$work/twotext-empty.bin" 1 0 4096
patch_text "$work/twotext-empty.bin" 192 '__TEXT'
check_fail "$work/twotext-empty.bin" 'a second __TEXT segment without sections fails'

# A section count over the cap fails even when the command size agrees. The
# record sits after the large command area so the cap is the only failure.
build_engine "$work/manysections.bin" 4097 -1 400000
# The generic builder writes small-fixture records at these offsets, which
# fall inside this large command area. Restore the unnamed sections to zero.
dd if=/dev/zero of="$work/manysections.bin" bs=1 seek=1024 count=128 conv=notrunc 2>/dev/null
dd if=/dev/zero of="$work/manysections.bin" bs=1 seek=2048 count=64 conv=notrunc 2>/dev/null
patch_u64 "$work/manysections.bin" "$O_SEG_FILESIZE" 400000
patch_u64 "$work/manysections.bin" 64 400000
patch_u32 "$work/manysections.bin" "$O_SECT_OFFSET" 350000
patch_u64 "$work/manysections.bin" 136 $((4294967296 + 350000))
write_record "$work/manysections.bin" 350000
check_fail "$work/manysections.bin" 'more than 4096 sections fail'

# ---------------------------------------------------------------------------
# The 64-byte record
# ---------------------------------------------------------------------------

record_case_text() {
  # record_case_text LABEL LENGTH TEXT
  cp "$base" "$work/case.bin"
  patch_text "$work/case.bin" "$O_RECORD_TEXT" "$3"
  patch_u8 "$work/case.bin" "$O_RECORD_LEN" "$2"
  check_fail "$work/case.bin" "$1"
}

cp "$base" "$work/case.bin"
patch_text "$work/case.bin" "$O_RECORD" 'XSSHVER1'
check_fail "$work/case.bin" 'a wrong record magic fails'

patch_case 'a record format other than 1 fails' patch_u8 "$O_RECORD_FORMAT" 2
patch_case 'a zero record format fails' patch_u8 "$O_RECORD_FORMAT" 0
patch_case 'a zero version length fails' patch_u8 "$O_RECORD_LEN" 0
patch_case 'a version length over 32 fails' patch_u8 "$O_RECORD_LEN" 33

record_case_text 'a version with two parts fails' 3 '1.2'
record_case_text 'a version with a double dot fails' 4 '1..2'
record_case_text 'a version with a leading dot fails' 4 '.1.2'
record_case_text 'a version with a trailing dot fails' 4 '1.2.'
record_case_text 'a version with four parts fails' 7 '1.2.3.4'
record_case_text 'a version with a letter fails' 5 '1.2.x'
record_case_text 'a version with a suffix fails' 11 '1.2.3-beta'
record_case_text 'a version length that stops mid-text fails' 4 '0.1.0'
record_case_text 'a version length that includes a NUL fails' 6 '0.1.0'

patch_case 'a nonzero padding byte fails' patch_u8 1039 65
patch_case 'a nonzero byte late in the padding fails' patch_u8 1087 1

# A record that the reader cannot read in full fails: the section must fit.
cp "$base" "$work/cut.bin"
patch_u32 "$work/cut.bin" "$O_SECT_OFFSET" 4088
check_fail "$work/cut.bin" 'a section that runs past the end of the file fails'

# A record that ends exactly at the end of the segment and the file is valid.
cp "$base" "$work/boundary.bin"
patch_u32 "$work/boundary.bin" "$O_SECT_OFFSET" 4032
patch_u64 "$work/boundary.bin" 136 4294971328
write_record "$work/boundary.bin" 4032
check_ok "$work/boundary.bin" 0.1.0 'a record at the exact end of the segment is accepted'

# ---------------------------------------------------------------------------
# External failures and short reads must not produce a version.
# The stubs are used only by the reader and leave the fixture untouched.
mkdir "$work/stubs"
for program in dd od tr wc; do
  printf '#!/bin/sh\nexit 1\n' > "$work/stubs/$program"
  chmod +x "$work/stubs/$program"
  status=0
  PATH="$work/stubs:$PATH" sh "$reader" "$base" > "$out" 2> "$err" || status=$?
  checks=$((checks + 1))
  [ "$status" -eq 1 ] && [ ! -s "$out" ] && [ "$(cat "$err")" = "$fixed_error" ] || fail "$program failure is reported"
  rm "$work/stubs/$program"
done
printf '#!/bin/sh\nexit 1\n' > "$work/bad-awk"
chmod +x "$work/bad-awk"
run_with_bad_awk=0
HS_AWK="$work/bad-awk" sh "$reader" "$base" > "$out" 2> "$err" || run_with_bad_awk=$?
checks=$((checks + 1))
[ "$run_with_bad_awk" -eq 1 ] && [ ! -s "$out" ] && [ "$(cat "$err")" = "$fixed_error" ] || fail 'awk failure is reported'
real_od=$(command -v od)
cat > "$work/stubs/od" <<EOF
#!/bin/sh
"$real_od" "\$@" | head -n 1
EOF
chmod +x "$work/stubs/od"
status=0
PATH="$work/stubs:$PATH" sh "$reader" "$base" > "$out" 2> "$err" || status=$?
checks=$((checks + 1))
[ "$status" -eq 1 ] && [ ! -s "$out" ] && [ "$(cat "$err")" = "$fixed_error" ] || fail 'a successful short read is rejected'
rm "$work/stubs/od"

cat > "$work/stubs/od" <<EOF
#!/bin/sh
case " \$* " in
  *" -N 64 "*) "$real_od" "\$@" | head -n 1 ;;
  *) exec "$real_od" "\$@" ;;
esac
EOF
chmod +x "$work/stubs/od"
status=0
PATH="$work/stubs:$PATH" sh "$reader" "$base" > "$out" 2> "$err" || status=$?
checks=$((checks + 1))
[ "$status" -eq 1 ] && [ ! -s "$out" ] && [ "$(cat "$err")" = "$fixed_error" ] || fail 'a short record read is rejected'
rm "$work/stubs/od"
status=0
HS_AWK="$work/missing-awk" sh "$reader" "$base" > "$out" 2> "$err" || status=$?
checks=$((checks + 1))
[ "$status" -eq 2 ] && [ ! -s "$out" ] && [ "$(cat "$err")" = 'macho_version: awk is unavailable' ] || fail 'missing awk is a setup error'

# Every available awk implementation
# ---------------------------------------------------------------------------

awk_paths=""
for candidate in awk gawk mawk nawk; do
  if ! command -v "$candidate" >/dev/null 2>&1; then
    continue
  fi
  candidate_path=$(command -v "$candidate")
  case " $awk_paths " in
    *" $candidate_path "*) ;;
    *) awk_paths="$awk_paths $candidate_path" ;;
  esac
done

# run_with_awk AWK FILE -> sets status, out, err
run_with_awk() {
  local awkbin=$1
  status=0
  : > "$out"
  : > "$err"
  HS_AWK="$awkbin" sh "$reader" "$2" > "$out" 2> "$err" || status=$?
  checks=$((checks + 1))
}

for candidate in $awk_paths; do
  candidate_name=$(basename "$candidate")
  run_with_awk "$candidate" "$base"
  [ "$status" -eq 0 ] || fail "awk $candidate_name exits 0 on the canonical fixture (got $status)"
  [ "$(cat "$out")" = 0.1.0 ] || fail "awk $candidate_name reads 0.1.0"
  [ ! -s "$err" ] || fail "awk $candidate_name wrote to stderr on success"
  run_with_awk "$candidate" "$work/duplicate.bin"
  [ "$status" -ne 0 ] || fail "awk $candidate_name rejects a duplicate section"
  [ "$(cat "$err")" = "$fixed_error" ] || fail "awk $candidate_name prints the fixed error"
  [ ! -s "$out" ] || fail "awk $candidate_name wrote to stdout on failure"
done
if [ "$(printf '%s\n' $awk_paths | grep -c . || true)" -lt 2 ]; then
  echo 'note: only one awk implementation is available; the GNU container leg widens the matrix' >&2
fi

# ---------------------------------------------------------------------------
# The real macOS release binary, when it is present
# ---------------------------------------------------------------------------

binary="$repo_dir/rust/target/release/hotspotshade"
if [ -f "$binary" ] && [ ! -h "$binary" ]; then
  run "$binary"
  if [ "$status" -ne 0 ]; then
    fail "the real release binary has no readable version record (exit $status)"
  else
    real_version=$(cat "$out")
    case "$real_version" in
      *[!0-9.]*|.*|*.|*..*) fail "the real release version is not N.N.N: $real_version" ;;
    esac
    real_dots=$(printf '%s' "$real_version" | tr -cd '.' | wc -c | tr -d ' ')
    [ "$real_dots" -eq 2 ] || fail "the real release version does not have two dots: $real_version"
    echo "note: the real release binary reports version $real_version" >&2

    # Patch a copy so a stale or copied record cannot be confused with a
    # version read from another file.
    grep -a -b -o 'HSSHVER1' "$binary" > "$work/hits.txt" 2>/dev/null || true
    if [ -s "$work/hits.txt" ]; then
      hit=$(head -n 1 "$work/hits.txt" | cut -d: -f1)
      cp "$binary" "$work/patched.bin"
      zero_region "$work/patched.bin" $((hit + 10)) 54
      patch_text "$work/patched.bin" $((hit + 10)) '9.8.7'
      patch_u8 "$work/patched.bin" $((hit + 9)) 5
      check_ok "$work/patched.bin" 9.8.7 'a patched copy of the real binary reads its own record'
      head -c $((hit + 32)) "$binary" > "$work/truncated.bin"
      check_fail "$work/truncated.bin" 'the real binary cut short fails'
    else
      echo 'note: the HSSHVER1 magic offset could not be located; the patch check is skipped' >&2
    fi
  fi
else
  echo 'note: rust/target/release/hotspotshade is absent; the real-binary check is skipped' >&2
fi

# ---------------------------------------------------------------------------
# GNU container leg
# ---------------------------------------------------------------------------

if [ "${HS_MACHO_TEST_NO_CONTAINER:-0}" = 1 ]; then
  echo 'note: the GNU container leg is skipped inside the container' >&2
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 &&
  docker image inspect debian:bookworm-slim >/dev/null 2>&1; then
  echo 'note: running the GNU container leg in debian:bookworm-slim with --network none' >&2
  checks=$((checks + 1))
  if docker run --rm --network none -v "$repo_dir:/src:ro" \
    -e HS_MACHO_TEST_NO_CONTAINER=1 \
    debian:bookworm-slim bash /src/scripts/tests/macho_version_test.sh \
    > "$work/container.log" 2>&1; then
    if grep -q '^FAIL:' "$work/container.log"; then
      fail 'the GNU container leg reported a failure'
      sed 's/^/    /' "$work/container.log" >&2
    fi
  else
    fail 'the GNU container leg failed to run'
    sed 's/^/    /' "$work/container.log" | tail -n 40 >&2
  fi
else
  echo 'note: docker or the debian:bookworm-slim image is unavailable; the GNU container leg is skipped' >&2
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

if [ "$failures" -ne 0 ]; then
  echo "MACHO_VERSION_TEST_FAILED failures=$failures checks=$checks" >&2
  exit 1
fi
echo "MACHO_VERSION_TEST_PASSED checks=$checks"
