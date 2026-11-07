#!/usr/bin/env bash
# Test scripts/artifact_versions.sh.
#
# The tests build small fake artifacts, prove that a matching version passes,
# and then break one property at a time. One fixture is the real binary
# Info.plist bytes from an iOS build (version 1.0), so the binary plist reader
# is checked against bytes that Apple tooling wrote and not only against a
# generator written for this test.
#
# Hermetic: no build, no network, no device, no route, no credential. Nothing
# runs an artifact.
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
checker="$repo_dir/scripts/artifact_versions.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/hs-artver-test.XXXXXXXX")
trap 'rm -rf "$work"' EXIT

failures=0
checks=0
out=""
status=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

run() {
  # run ARGS...  -> sets out and status
  status=0
  out=$(sh "$checker" "$@" 2>&1) || status=$?
  checks=$((checks + 1))
}

run_awk() {
  # run_awk AWK ARGS... -> sets out and status
  local awkbin=$1
  shift
  status=0
  out=$(HS_AWK="$awkbin" sh "$checker" "$@" 2>&1) || status=$?
  checks=$((checks + 1))
}

expect_status() {
  if [ "$status" -ne "$1" ]; then
    fail "$2 (expected exit $1, got $status)"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

expect_text() {
  if ! printf '%s\n' "$out" | grep -F -- "$1" >/dev/null; then
    fail "$2 (missing: $1)"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

reject_text() {
  if printf '%s\n' "$out" | grep -F -- "$1" >/dev/null; then
    fail "$2 (unexpected: $1)"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

for tool in zip unzip gzip awk od tail head cut tr dd wc perl find; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "FAIL: $tool is missing; the artifact version tests cannot run" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

# xml_plist FILE SHORT [BUILD]
# An XML plist shaped like the Xcode output, including a nested array and dict
# so that a nested key cannot be mistaken for a top-level key.
xml_plist() {
  cat > "$1" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>local.test</string>
	<key>CFBundleSupportedPlatforms</key>
	<array>
		<string>MacOSX</string>
	</array>
	<key>CFBundleShortVersionString</key>
	<string>$2</string>
	<key>CFBundleVersion</key>
	<string>${3:-1}</string>
	<key>LSRequiresIPhoneOS</key>
	<true/>
</dict>
</plist>
EOF
}

# bin_plist FILE KEY VALUE [KEY VALUE ...]
# A bplist00 file with a top-level dictionary of ASCII strings. Offsets use two
# bytes and object references use one byte. Written with awk and printf only.
bin_plist() {
  local file=$1
  shift
  local esc
  esc=$(printf '%s\n' "$@" | awk '
    function emit(b) { bytes[nb++] = b }
    # A "u:" prefix writes a UTF-16 string object (0x6N) and an "8:" prefix a
    # UTF-8 string object (0x7N). No prefix writes an ASCII object (0x5N).
    function emit_str(s,   l, k, t) {
      t = 80
      if (substr(s, 1, 2) == "u:") { t = 96; s = substr(s, 3) }
      else if (substr(s, 1, 2) == "8:") { t = 112; s = substr(s, 3) }
      l = length(s)
      off[no++] = nb
      if (l < 15) emit(t + l)
      else { emit(t + 15); emit(16); emit(l) }
      for (k = 1; k <= l; k++) {
        if (t == 96) emit(0)
        emit(ord[substr(s, k, 1)])
      }
    }
    BEGIN { for (c = 32; c < 127; c++) ord[sprintf("%c", c)] = c }
    { arg[na++] = $0 }
    END {
      pairs = na / 2
      for (k = 0; k < 8; k++) emit(substr("bplist00", k + 1, 1) == "" ? 0 : ord[substr("bplist00", k + 1, 1)])
      # Object 0 is the dictionary. Its offset is recorded first.
      off[no++] = nb
      emit(208 + pairs)
      for (i = 0; i < pairs; i++) emit(1 + i)
      for (i = 0; i < pairs; i++) emit(1 + pairs + i)
      for (i = 0; i < pairs; i++) emit_str(arg[2 * i])
      for (i = 0; i < pairs; i++) emit_str(arg[2 * i + 1])
      tbl = nb
      for (i = 0; i < no; i++) { emit(int(off[i] / 256)); emit(off[i] % 256) }
      for (k = 0; k < 6; k++) emit(0)
      emit(2); emit(1)
      for (k = 0; k < 7; k++) emit(0); emit(no)
      for (k = 0; k < 8; k++) emit(0)
      for (k = 0; k < 6; k++) emit(0); emit(int(tbl / 256)); emit(tbl % 256)
      # The first dictionary entry took offset 8, so object 0 starts the objects.
      for (k = 0; k < nb; k++) printf "\\%03o", bytes[k]
    }
  ')
  printf "$esc" > "$file"
}

# hex_to_file HEX FILE
# Write bytes from a hex string. awk and printf only.
hex_to_file() {
  local esc
  esc=$(printf '%s' "$1" | awk '
    BEGIN { for (i = 0; i < 16; i++) v[substr("0123456789abcdef", i + 1, 1)] = i }
    { s = s $0 }
    END {
      for (i = 1; i + 1 <= length(s); i += 2)
        printf "\\%03o", v[substr(s, i, 1)] * 16 + v[substr(s, i + 1, 1)]
    }')
  printf "$esc" > "$2"
}

# The real Info.plist from an iOS build: 1610 bytes, 31 keys, version "1.0".
# Captured from an unsigned IPA built by scripts/build_ipa.sh. 64 bytes a line.
write_real_ios_plist() {
  hex_to_file "$(tr -d '\n' <<'HEX'
62706c6973743030df101f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242c303123323334363738393a383b3c3d3e
3f40414245474a4b4d5f10134275696c644d616368696e654f534275696c645f1019434642756e646c65446576656c6f706d656e74526567696f6e5f10134346
42756e646c65446973706c61794e616d655f1012434642756e646c6545786563757461626c655d434642756e646c6549636f6e735f1012434642756e646c6549
636f6e737e697061645f1012434642756e646c654964656e7469666965725f101d434642756e646c65496e666f44696374696f6e61727956657273696f6e5c43
4642756e646c654e616d655f1013434642756e646c655061636b616765547970655f101a434642756e646c6553686f727456657273696f6e537472696e675f10
1a434642756e646c65537570706f72746564506c6174666f726d735f100f434642756e646c6556657273696f6e5a4454436f6d70696c65725f100f4454506c61
74666f726d4275696c645e4454506c6174666f726d4e616d655f10114454506c6174666f726d56657273696f6e5a445453444b4275696c6459445453444b4e61
6d6557445458636f64655c445458636f64654275696c645f10124c5352657175697265734950686f6e654f535f10104d696e696d756d4f5356657273696f6e5f
101e4e534c6f63616c4e6574776f726b55736167654465736372697074696f6e5f10234e534c6f636174696f6e5768656e496e55736555736167654465736372
697074696f6e5f101a55494170706c69636174696f6e5363656e654d616e69666573745f101155494261636b67726f756e644d6f6465735e5549446576696365
46616d696c795e55494c61756e636853637265656e5f101c554952657175697265644465766963654361706162696c69746965735f10205549537570706f7274
6564496e746572666163654f7269656e746174696f6e7355323547383352656e5c486f7473706f7453686164655c486f7473706f7450726f7879d125265f1013
434642756e646c655072696d61727949636f6ed22728292b5f1011434642756e646c6549636f6e46696c65735f1010434642756e646c6549636f6e4e616d65a1
2a5c41707049636f6e36307836305741707049636f6ed1252dd227282e2ba22a2f5c41707049636f6e37367837365f10166c6f63616c2e686f7473706f747072
6f78792e61707053362e30544150504c53312e30a135586950686f6e654f5351315f1022636f6d2e6170706c652e636f6d70696c6572732e6c6c766d2e636c61
6e672e315f3056323346383161586970686f6e656f735432362e355c6970686f6e656f7332362e35543236363056313746313133095431372e305f1046416363
65707420534f434b5320636f6e6e656374696f6e732066726f6d20796f75722074617267657420646576696365206f6e20746865206c6f63616c20686f747370
6f742e5f105d4c6f636174696f6e2068656c7073206b656570207468652070726f78792072756e6e696e6720696e20746865206261636b67726f756e642e2054
68652061707020646f6573206e6f74207361766520796f7572206c6f636174696f6e2ed143445f102355494170706c69636174696f6e537570706f7274734d75
6c7469706c655363656e657308a146586c6f636174696f6ea2484910011002d0a14c5561726d3634a44e4f50515f101e5549496e746572666163654f7269656e
746174696f6e506f7274726169745f10285549496e746572666163654f7269656e746174696f6e506f727472616974557073696465446f776e5f10235549496e
746572666163654f7269656e746174696f6e4c616e6473636170654c6566745f10245549496e746572666163654f7269656e746174696f6e4c616e6473636170
65526967687400080049005f007b009100a600b400c900de00fe010b0121013e015b016d0178018a019901ad01b801c201ca01d701ec01ff0220024602630277
0286029502b402d702dd02e002ed02fa02fd03130318032c033f0341034e03560359035e0361036e0387038b039003940396039f03a103c603cd03d603db03e8
03ed03f403f503fa044304a304a604cc04cd04cf04d804db04dd04df04e004e204e804ed050e0539055f00000000000002010000000000000052000000000000
00000000000000000586
HEX
)" "$1"
}

# make_ipa OUT PLIST [APPNAME]: a zip with Payload/APP.app/Info.plist and a binary.
make_ipa() {
  local out=$1 plist=$2 app=${3:-HotspotProxy} d
  d=$(mktemp -d "$work/ipa.XXXXXX")
  mkdir -p "$d/Payload/$app.app"
  cp "$plist" "$d/Payload/$app.app/Info.plist"
  printf 'x' > "$d/Payload/$app.app/$app"
  rm -f "$out"
  (cd "$d" && zip -qr "$out" Payload)
}

# make_macho FILE [ok|x86|fat|filetype|short|text]
# A 4096-byte synthetic little-endian 64-bit arm64 Mach-O executable with one
# 8-byte load command. The variants break one header property at a time.
make_macho() {
  local file=$1 variant=${2:-ok} size=4096 have
  case "$variant" in
    short) size=128 ;;
  esac
  {
    case "$variant" in
      fat)
        printf '\312\376\272\276'
        ;;
      x86)
        printf '\317\372\355\376\007\000\000\001\000\000\000\000\002\000\000\000\001\000\000\000\010\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\010\000\000\000'
        ;;
      filetype)
        printf '\317\372\355\376\014\000\000\001\000\000\000\000\001\000\000\000\001\000\000\000\010\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\010\000\000\000'
        ;;
      *)
        printf '\317\372\355\376\014\000\000\001\000\000\000\000\002\000\000\000\001\000\000\000\010\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\010\000\000\000'
        ;;
    esac
    if [ "$variant" = text ]; then
      printf '<div class="side-meta">v0.1.0 </div>'
    fi
  } > "$file"
  have=$(wc -c < "$file" | tr -d ' ')
  if [ "$have" -lt "$size" ]; then
    head -c $((size - have)) /dev/zero >> "$file"
  fi
}

# make_mac_zip OUT PLIST [with-engine|no-engine] [MACHO-VARIANT]
make_mac_zip() {
  local out=$1 plist=$2 engine=${3:-with-engine} variant=${4:-ok} d
  d=$(mktemp -d "$work/mac.XXXXXX")
  mkdir -p "$d/HotspotShade.app/Contents/MacOS" "$d/HotspotShade.app/Contents/Resources/bin"
  cp "$plist" "$d/HotspotShade.app/Contents/Info.plist"
  printf 'x' > "$d/HotspotShade.app/Contents/MacOS/HotspotShade"
  [ "$engine" = with-engine ] && make_macho "$d/HotspotShade.app/Contents/Resources/bin/hotspotshade" "$variant"
  rm -f "$out"
  (cd "$d" && zip -qr "$out" HotspotShade.app)
}

# le16 N / le32 N: little-endian bytes as a printf format.
le16() { printf '\\x%02x\\x%02x' $(($1 & 255)) $((($1 >> 8) & 255)); }
le32() { le16 $(($1 & 65535)); le16 $((($1 >> 16) & 65535)); }

# raw_zip OUT NAME...
# A zip of empty stored files whose names are written exactly as given (printf
# %b escapes allowed). The zip tool normalizes names, so odd names need this
# writer. An empty file has CRC 0, so the archive is valid. A name that ends
# in a slash is a directory entry.
raw_zip() {
  local out=$1 name nfile off=0 count=0 cd_size=0 cd_off
  shift
  nfile="$work/raw.name"
  : > "$out.cd"
  : > "$out"
  for name in "$@"; do
    printf '%b' "$name" > "$nfile"
    local len attr
    len=$(wc -c < "$nfile" | tr -d ' ')
    attr=$((0100644 << 16))
    case "$name" in */) attr=$((040755 << 16)) ;; esac
    {
      printf 'PK\003\004'; printf "$(le16 10)$(le16 0)$(le16 0)$(le16 0)$(le16 0)"
      printf "$(le32 0)$(le32 0)$(le32 0)$(le16 "$len")$(le16 0)"
      cat "$nfile"
    } >> "$out"
    {
      printf 'PK\001\002'; printf "$(le16 788)$(le16 10)$(le16 0)$(le16 0)$(le16 0)$(le16 0)"
      printf "$(le32 0)$(le32 0)$(le32 0)$(le16 "$len")$(le16 0)$(le16 0)$(le16 0)$(le16 0)"
      printf "$(le32 "$attr")$(le32 "$off")"
      cat "$nfile"
    } >> "$out.cd"
    off=$((off + 30 + len))
    count=$((count + 1))
  done
  cd_off=$off
  cd_size=$(wc -c < "$out.cd" | tr -d ' ')
  cat "$out.cd" >> "$out"
  rm -f "$out.cd"
  {
    printf 'PK\005\006'
    printf "$(le16 0)$(le16 0)$(le16 "$count")$(le16 "$count")$(le32 "$cd_size")$(le32 "$cd_off")$(le16 0)"
  } >> "$out"
}

# patch_le16 FILE OFFSET VALUE / patch_le32 FILE OFFSET VALUE
# Overwrite a little-endian field in a fixture. OFFSET is zero-based.
patch_le16() {
  printf "$(le16 "$3")" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

patch_le32() {
  printf "$(le32 "$3")" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

# zip_crc_file FILE: ZIP CRC-32 from the gzip trailer.
zip_crc_file() {
  gzip -n -c "$1" 2>/dev/null | tail -c 8 | head -c 4 | od -An -v -tu1 |
    awk 'NF == 4 { printf "%.0f\n", $1 + 256 * $2 + 65536 * $3 + 16777216 * $4 }'
}

# raw_zip_spec OUT SPEC
# Build a zip from a specification file. Each line has ten | separated fields:
#   local_name|central_name|content_file|mode|flags|method|local|central|local_extra_hex|central_extra_hex
# A name is written with printf %b, so backslash escapes are allowed. local and
# central are 1 or 0. An empty mode defaults from the trailing slash. The
# content is stored (method 0) and its ZIP CRC is computed from the gzip
# trailer. A set bit 3 writes a data descriptor after the data.
raw_zip_spec() {
  local out=$1 spec=$2
  local cd="$work/raw.cd.$$" off=0 count=0
  local lname cname content mode flags method inc_l inc_c lext cext
  local data_size crc=0 local_crc local_csize local_usize
  local lfile nfile lextfile cextfile nlen elen clen
  : > "$out"; : > "$cd"; : > "$work/raw.empty"
  while IFS='|' read -r lname cname content mode flags method inc_l inc_c lext cext; do
    [ -n "$lname$cname" ] || continue
    [ -n "$content" ] || content="$work/raw.empty"
    [ -n "$mode" ] || { case "$lname$cname" in */) mode=040755 ;; *) mode=0100644 ;; esac; }
    [ -n "$flags" ] || flags=0
    [ -n "$method" ] || method=0
    [ -n "$inc_l" ] || inc_l=1
    [ -n "$inc_c" ] || inc_c=1
    data_size=$(wc -c < "$content" | tr -d ' ')
    if [ "$data_size" -gt 0 ]; then
      crc=$(zip_crc_file "$content")
    fi
    local_crc=$crc; local_csize=$data_size; local_usize=$data_size
    printf '%b' "$lname" > "$work/raw.lname"
    printf '%b' "$cname" > "$work/raw.cname"
    if [ -n "$lext" ]; then hex_to_file "$lext" "$work/raw.lext"; else : > "$work/raw.lext"; fi
    if [ -n "$cext" ]; then hex_to_file "$cext" "$work/raw.cext"; else : > "$work/raw.cext"; fi
    local_off=$off
    if [ "$inc_l" = 1 ]; then
      nlen=$(wc -c < "$work/raw.lname" | tr -d ' ')
      elen=$(wc -c < "$work/raw.lext" | tr -d ' ')
      if [ $((flags / 8 % 2)) -eq 1 ]; then
        local_crc=0; local_csize=0; local_usize=0
      fi
      {
        printf 'PK\003\004'; printf "$(le16 20)$(le16 "$flags")$(le16 "$method")"
        printf "$(le16 0)$(le16 0)$(le32 "$local_crc")"
        printf "$(le32 "$local_csize")$(le32 "$local_usize")"
        printf "$(le16 "$nlen")$(le16 "$elen")"
        cat "$work/raw.lname" "$work/raw.lext" "$content"
        if [ $((flags / 8 % 2)) -eq 1 ]; then
          printf 'PK\007\010'; printf "$(le32 "$crc")$(le32 "$data_size")$(le32 "$data_size")"
        fi
      } >> "$out"
      off=$((off + 30 + nlen + elen + data_size))
      if [ $((flags / 8 % 2)) -eq 1 ]; then off=$((off + 16)); fi
    fi
    if [ "$inc_c" = 1 ]; then
      nlen=$(wc -c < "$work/raw.cname" | tr -d ' ')
      elen=$(wc -c < "$work/raw.cext" | tr -d ' ')
      {
        printf 'PK\001\002'; printf "$(le16 788)$(le16 20)$(le16 "$flags")$(le16 "$method")"
        printf "$(le16 0)$(le16 0)$(le32 "$crc")$(le32 "$data_size")$(le32 "$data_size")"
        printf "$(le16 "$nlen")$(le16 "$elen")$(le16 0)$(le16 0)$(le16 0)"
        printf "$(le32 "$((mode << 16))")$(le32 "$local_off")"
        cat "$work/raw.cname" "$work/raw.cext"
      } >> "$cd"
      count=$((count + 1))
    fi
  done < "$spec"
  local cd_size cd_off
  cd_off=$off
  cd_size=$(wc -c < "$cd" | tr -d ' ')
  cat "$cd" >> "$out"
  {
    printf 'PK\005\006'
    printf "$(le16 0)$(le16 0)$(le16 "$count")$(le16 "$count")$(le32 "$cd_size")$(le32 "$cd_off")$(le16 0)"
  } >> "$out"
  rm -f "$cd" "$work/raw.lname" "$work/raw.cname" "$work/raw.lext" "$work/raw.cext"
}

mkdir -p "$work/p"
xml_plist "$work/p/good.xml" 0.1.0
xml_plist "$work/p/old.xml" 1.0
xml_plist "$work/p/drift.xml" 0.1.1
xml_plist "$work/p/unexpanded.xml" '$(MARKETING_VERSION)'
bin_plist "$work/p/good.bin" CFBundleShortVersionString 0.1.0 CFBundleVersion 1 CFBundleIdentifier local.test
bin_plist "$work/p/drift.bin" CFBundleShortVersionString 0.1.1 CFBundleVersion 1
bin_plist "$work/p/long.bin" CFBundleName ThisIsAKeyValueLongerThanFifteenCharacters CFBundleShortVersionString 0.1.0
bin_plist "$work/p/missing.bin" CFBundleVersion 1 CFBundleName Test
bin_plist "$work/p/dup.bin" CFBundleShortVersionString 0.1.0 CFBundleShortVersionString 0.1.0
write_real_ios_plist "$work/p/real.bin"

# ---------------------------------------------------------------------------
# Plist reading, through the IPA path
# ---------------------------------------------------------------------------

make_ipa "$work/good-xml.ipa" "$work/p/good.xml"
run --expected-version 0.1.0 --ipa "$work/good-xml.ipa"
expect_status 0 "an IPA with a matching XML plist passes"
expect_text "PASS  good-xml.ipa: CFBundleShortVersionString is 0.1.0" "the XML plist version is read"

make_ipa "$work/good-bin.ipa" "$work/p/good.bin"
run --expected-version 0.1.0 --ipa "$work/good-bin.ipa"
expect_status 0 "an IPA with a matching binary plist passes"
expect_text "PASS  good-bin.ipa: CFBundleShortVersionString is 0.1.0" "the binary plist version is read"

make_ipa "$work/long.ipa" "$work/p/long.bin"
run --expected-version 0.1.0 --ipa "$work/long.ipa"
expect_status 0 "a binary plist with a string over 15 bytes passes"

make_ipa "$work/real.ipa" "$work/p/real.bin"
run --expected-version 0.1.0 --ipa "$work/real.ipa"
expect_status 1 "the real iOS plist (version 1.0) fails against 0.1.0"
expect_text "CFBundleShortVersionString is 1.0, expected 0.1.0" "the real binary plist version is read exactly"

# Cross-check the reader against Apple's own converter when it is present.
if command -v plutil >/dev/null 2>&1; then
  plutil -convert binary1 -o "$work/p/plutil.bin" "$work/p/good.xml"
  make_ipa "$work/plutil.ipa" "$work/p/plutil.bin"
  run --expected-version 0.1.0 --ipa "$work/plutil.ipa"
  expect_status 0 "a plutil-written binary plist passes"
  plutil -convert binary1 -o "$work/p/plutil-old.bin" "$work/p/old.xml"
  make_ipa "$work/plutil-old.ipa" "$work/p/plutil-old.bin"
  run --expected-version 0.1.0 --ipa "$work/plutil-old.ipa"
  expect_status 1 "a plutil-written plist with 1.0 fails"
else
  echo "note: plutil is unavailable; the converter cross-check is skipped" >&2
fi

make_ipa "$work/old.ipa" "$work/p/old.xml"
run --expected-version 0.1.0 --ipa "$work/old.ipa"
expect_status 1 "an IPA that says 1.0 fails"
expect_text "FAIL  old.ipa: CFBundleShortVersionString is 1.0, expected 0.1.0" "the drift names both versions"

make_ipa "$work/drift.ipa" "$work/p/drift.xml"
run --expected-version 0.1.0 --ipa "$work/drift.ipa"
expect_status 1 "an IPA with 0.1.1 fails"
make_ipa "$work/drift-bin.ipa" "$work/p/drift.bin"
run --expected-version 0.1.0 --ipa "$work/drift-bin.ipa"
expect_status 1 "a binary plist with 0.1.1 fails"

make_ipa "$work/unexpanded.ipa" "$work/p/unexpanded.xml"
run --expected-version 0.1.0 --ipa "$work/unexpanded.ipa"
expect_status 1 "an unexpanded build variable fails"

make_ipa "$work/missing.ipa" "$work/p/missing.bin"
run --expected-version 0.1.0 --ipa "$work/missing.ipa"
expect_status 1 "a plist without the version key fails"
expect_text "cannot read CFBundleShortVersionString" "the missing key is named"

make_ipa "$work/dup.ipa" "$work/p/dup.bin"
run --expected-version 0.1.0 --ipa "$work/dup.ipa"
expect_status 1 "a duplicate version key is ambiguous and fails"

# The version key only inside a nested dictionary is not the bundle version.
cat > "$work/p/nested.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Other</key>
	<dict>
		<key>CFBundleShortVersionString</key>
		<string>0.1.0</string>
	</dict>
</dict>
</plist>
XML
make_ipa "$work/nested.ipa" "$work/p/nested.xml"
run --expected-version 0.1.0 --ipa "$work/nested.ipa"
expect_status 1 "a nested version key does not count"

# The version key whose value is not a string does not count.
cat > "$work/p/nonstring.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<integer>1</integer>
</dict>
</plist>
XML
make_ipa "$work/nonstring.ipa" "$work/p/nonstring.xml"
run --expected-version 0.1.0 --ipa "$work/nonstring.ipa"
expect_status 1 "a non-string version value fails"

# A hostile value must not reach the log raw.
printf '<?xml version="1.0"?>\n<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>0.1.0\033[31mX</string></dict></plist>\n' > "$work/p/hostile.xml"
make_ipa "$work/hostile.ipa" "$work/p/hostile.xml"
run --expected-version 0.1.0 --ipa "$work/hostile.ipa"
expect_status 1 "a value with control characters fails"
expect_text "an element has a control character" "the hostile value is refused before it is echoed"
if printf '%s' "$out" | grep "$(printf '\033')" >/dev/null; then
  fail "an escape character reached the output"
fi

# Garbage and truncated binary plists must fail without hanging.
printf 'bplist00\001\002' > "$work/p/trunc.bin"
make_ipa "$work/trunc.ipa" "$work/p/trunc.bin"
run --expected-version 0.1.0 --ipa "$work/trunc.ipa"
expect_status 1 "a truncated binary plist fails"
head -c 600 "$work/p/real.bin" > "$work/p/cut.bin"
make_ipa "$work/cut.ipa" "$work/p/cut.bin"
run --expected-version 0.1.0 --ipa "$work/cut.ipa"
expect_status 1 "a real plist cut short fails"
# Corrupt the trailer offset table position of the real plist.
{ head -c 1578 "$work/p/real.bin"; printf '\377\377\377\377\377\377\377\377'; } > "$work/p/badtrailer.bin"
make_ipa "$work/badtrailer.ipa" "$work/p/badtrailer.bin"
run --expected-version 0.1.0 --ipa "$work/badtrailer.ipa"
expect_status 1 "a binary plist with a wild trailer fails"
: > "$work/p/empty.plist"
make_ipa "$work/emptyplist.ipa" "$work/p/empty.plist"
run --expected-version 0.1.0 --ipa "$work/emptyplist.ipa"
expect_status 1 "an empty plist fails"

# Size bound: a plist over 262144 bytes is refused, not parsed.
{ cat "$work/p/good.xml"; head -c 270000 /dev/zero | tr '\0' ' '; } > "$work/p/huge.xml"
make_ipa "$work/huge.ipa" "$work/p/huge.xml"
run --expected-version 0.1.0 --ipa "$work/huge.ipa"
expect_status 1 "an oversized plist fails"
expect_text "larger than 262144 bytes" "the size bound is named"

# ---------------------------------------------------------------------------
# Archive shape
# ---------------------------------------------------------------------------

run --expected-version 0.1.0 --ipa "$work/does-not-exist.ipa"
expect_status 1 "a missing IPA fails"

printf 'not a zip' > "$work/garbage.ipa"
run --expected-version 0.1.0 --ipa "$work/garbage.ipa"
expect_status 1 "a file that is not a zip fails"

# Two app bundles.
d="$work/two"; mkdir -p "$d/Payload/A.app" "$d/Payload/B.app"
cp "$work/p/good.xml" "$d/Payload/A.app/Info.plist"; cp "$work/p/good.xml" "$d/Payload/B.app/Info.plist"
(cd "$d" && zip -qr "$work/two.ipa" Payload)
run --expected-version 0.1.0 --ipa "$work/two.ipa"
expect_status 1 "two app bundles fail"
expect_text "exactly one app bundle" "the ambiguity is named"

# A nested framework plist must not stand in for the bundle plist.
d="$work/fw"; mkdir -p "$d/Payload/A.app/Frameworks/F.framework"
cp "$work/p/good.xml" "$d/Payload/A.app/Frameworks/F.framework/Info.plist"
(cd "$d" && zip -qr "$work/fw.ipa" Payload)
run --expected-version 0.1.0 --ipa "$work/fw.ipa"
expect_status 1 "only a nested Info.plist fails"
expect_text "expected exactly one top-level bundle Info.plist at Payload/A.app/Info.plist" "the missing top-level plist is named"

# A nested plist next to the real one is ignored.
d="$work/fw2"; mkdir -p "$d/Payload/A.app/Frameworks/F.framework"
cp "$work/p/good.xml" "$d/Payload/A.app/Info.plist"
cp "$work/p/old.xml" "$d/Payload/A.app/Frameworks/F.framework/Info.plist"
(cd "$d" && zip -qr "$work/fw2.ipa" Payload)
run --expected-version 0.1.0 --ipa "$work/fw2.ipa"
expect_status 0 "a nested Info.plist beside the bundle plist is ignored"

# Path traversal entry.
d="$work/trav"; mkdir -p "$d/Payload/A.app" "$d/sub"
cp "$work/p/good.xml" "$d/Payload/A.app/Info.plist"; printf x > "$d/outside"
(cd "$d" && zip -qr "$work/trav.ipa" Payload && cd sub && zip -q "$work/trav.ipa" ../outside)
run --expected-version 0.1.0 --ipa "$work/trav.ipa"
expect_status 1 "a parent-directory entry fails"
expect_text "an entry name has a dot or parent path component" "the unsafe path is named"

# Symbolic link entry.
d="$work/sym"; mkdir -p "$d/Payload/A.app"
cp "$work/p/good.xml" "$d/Payload/A.app/Info.plist"; ln -s /etc/passwd "$d/Payload/A.app/link"
(cd "$d" && zip -qry "$work/sym.ipa" Payload)
run --expected-version 0.1.0 --ipa "$work/sym.ipa"
expect_status 1 "a symbolic link entry fails"
expect_text "an entry is a special file type" "the link is named"

# Info.plist symlinked to another file must not be followed or read.
d="$work/symplist"; mkdir -p "$d/Payload/A.app"
ln -s ../../../good.xml "$d/Payload/A.app/Info.plist"; cp "$work/p/good.xml" "$d/good.xml"
(cd "$d" && zip -qry "$work/symplist.ipa" Payload)
run --expected-version 0.1.0 --ipa "$work/symplist.ipa"
expect_status 1 "a symlinked Info.plist fails"

# Duplicate entry name. The writer can put the same name in two local headers
# and two central-directory entries.
real_unzip=$(command -v unzip)
raw_zip "$work/dupname.ipa" "Payload/A.app/Info.plist" "Payload/A.app/Info.plist"
run --expected-version 0.1.0 --ipa "$work/dupname.ipa"
expect_status 1 "a repeated entry name fails"
expect_text "two entry names are identical" "the repeat is named"

# Entry count bound. A raw archive with one entry has its end record patched to
# claim 20001 entries, so the bound fires before any entry is parsed.
raw_zip "$work/count.ipa" "Payload/A.app/Info.plist"
size=$(wc -c < "$work/count.ipa" | tr -d ' ')
patch_le16 "$work/count.ipa" $((size - 22 + 8)) 20001
patch_le16 "$work/count.ipa" $((size - 22 + 10)) 20001
run --expected-version 0.1.0 --ipa "$work/count.ipa"
expect_status 1 "an archive with too many entries fails"
expect_text "more than 20000 entries" "the entry bound is named"

# Central-directory size bound. The end record claims a directory over 4 MiB.
raw_zip "$work/cdmax.ipa" "Payload/A.app/Info.plist"
size=$(wc -c < "$work/cdmax.ipa" | tr -d ' ')
patch_le32 "$work/cdmax.ipa" $((size - 22 + 12)) 4194305
run --expected-version 0.1.0 --ipa "$work/cdmax.ipa"
expect_status 1 "an oversized central directory fails"
expect_text "the central directory is larger than 4194304 bytes" "the directory bound is named"

# A path with glob characters must not reach unzip as a pattern.
d="$work/glob"; mkdir -p "$d/Payload/A[1].app"
cp "$work/p/good.xml" "$d/Payload/A[1].app/Info.plist"
(cd "$d" && zip -qr "$work/glob.ipa" Payload)
run --expected-version 0.1.0 --ipa "$work/glob.ipa"
expect_status 1 "a bundle name with glob characters is refused"
expect_text "an entry name has a byte outside the safe printable ASCII set" "the refusal is explained"

# A symlinked archive is refused by name in --artifacts mode and as a file.
ln -s "$work/good-xml.ipa" "$work/link.ipa"
run --expected-version 0.1.0 --ipa "$work/link.ipa"
expect_status 1 "a symlinked IPA fails"

# ---------------------------------------------------------------------------
# Ambiguous archive names (written by raw_zip, because zip normalizes them)
# ---------------------------------------------------------------------------

# Control: the same writer with plain names reaches the plist read. The entry is
# empty, so the failure is the plist and not a name rule.
raw_zip "$work/raw-ok.ipa" "Payload/" "Payload/A.app/" "Payload/A.app/Info.plist"
run --expected-version 0.1.0 --ipa "$work/raw-ok.ipa"
expect_status 1 "the raw zip control has an empty plist"
expect_text "the Info.plist size is empty" "the control passes every name rule"

raw_zip "$work/dot1.ipa" "Payload/./A.app/Info.plist"
run --expected-version 0.1.0 --ipa "$work/dot1.ipa"
expect_status 1 "a dot component fails"
expect_text "dot or parent path component" "the dot component is named"

raw_zip "$work/dot2.ipa" "Payload/A.app/./Info.plist"
run --expected-version 0.1.0 --ipa "$work/dot2.ipa"
expect_status 1 "a dot component before the file name fails"
expect_text "dot or parent path component" "the dot component is named again"

raw_zip "$work/empty1.ipa" "Payload//A.app/Info.plist"
run --expected-version 0.1.0 --ipa "$work/empty1.ipa"
expect_status 1 "an empty component fails"
expect_text "empty path component" "the empty component is named"

raw_zip "$work/dotdir.ipa" "Payload/A.app/Info.plist" "Payload/."
run --expected-version 0.1.0 --ipa "$work/dotdir.ipa"
expect_status 1 "a trailing dot entry fails"

raw_zip "$work/dotslash.ipa" "Payload/A.app/Info.plist" "Payload/A.app//"
run --expected-version 0.1.0 --ipa "$work/dotslash.ipa"
expect_status 1 "a doubled trailing slash fails"
expect_text "empty path component" "the doubled slash is named"

raw_zip "$work/abs.ipa" "/Payload/A.app/Info.plist"
run --expected-version 0.1.0 --ipa "$work/abs.ipa"
expect_status 1 "an absolute entry fails"
expect_text "an entry name is absolute" "the absolute path is named"

raw_zip "$work/dotdot.ipa" "Payload/A.app/../B.app/Info.plist"
run --expected-version 0.1.0 --ipa "$work/dotdot.ipa"
expect_status 1 "an embedded parent component fails"

raw_zip "$work/back.ipa" 'Payload/A.app\\Info.plist'
run --expected-version 0.1.0 --ipa "$work/back.ipa"
expect_status 1 "a backslash entry fails"

raw_zip "$work/case.ipa" "Payload/A.app/Info.plist" "Payload/A.app/info.plist"
run --expected-version 0.1.0 --ipa "$work/case.ipa"
expect_status 1 "names that differ only in case fail"
expect_text "differ only in case" "the case collision is named"

raw_zip "$work/case2.ipa" "Payload/A.app/Info.plist" "payload/a.app/"
run --expected-version 0.1.0 --ipa "$work/case2.ipa"
expect_status 1 "a directory that differs only in case fails"
expect_text "differ only in case" "the directory case collision is named"

raw_zip "$work/filedir.ipa" "Payload/A.app/Info.plist" "Payload/A.app/Info.plist/"
run --expected-version 0.1.0 --ipa "$work/filedir.ipa"
expect_status 1 "a name that is a file and a directory fails"
expect_text "both a file and a directory" "the file and directory clash is named"

raw_zip "$work/filepre.ipa" "Payload/A.app" "Payload/A.app/Info.plist"
run --expected-version 0.1.0 --ipa "$work/filepre.ipa"
expect_status 1 "a file used as a directory fails"
expect_text "both a file and a directory" "the file used as a directory is named"

raw_zip "$work/nonascii.ipa" 'Payload/A.app/Info.plist' 'Payload/A.app/caf\303\251'
run --expected-version 0.1.0 --ipa "$work/nonascii.ipa"
expect_status 1 "a non-ASCII entry name fails"
expect_text "byte outside the safe printable ASCII set" "the non-ASCII name is named"

raw_zip "$work/ctrl.ipa" 'Payload/A.app/Info.plist' 'Payload/A.app/x\033[31m'
run --expected-version 0.1.0 --ipa "$work/ctrl.ipa"
expect_status 1 "a control character in an entry name fails"
if printf '%s' "$out" | grep "$(printf '\033')" >/dev/null; then
  fail "an escape character from an entry name reached the output"
fi

# A newline in a name is a byte outside the safe printable set.
raw_zip "$work/nl.ipa" 'Payload/A.app/Info.plist' 'Payload/A.app/x\nPayload/B.app/Info.plist'
run --expected-version 0.1.0 --ipa "$work/nl.ipa"
expect_status 1 "a newline in an entry name fails"
expect_text "byte outside the safe printable ASCII set" "the newline is named"

# ---------------------------------------------------------------------------
# Archive bounds
# ---------------------------------------------------------------------------

# An archive over 1 GiB is refused before any listing. The file is sparse.
dd if=/dev/null of="$work/big.ipa" bs=1 seek=1073741825 2>/dev/null
run --expected-version 0.1.0 --ipa "$work/big.ipa"
expect_status 1 "an archive over 1 GiB fails"
expect_text "the archive is larger than 1073741824 bytes" "the archive size bound is named"
rm -f "$work/big.ipa"

# ---------------------------------------------------------------------------
# Raw ZIP structure: central directory versus local headers
# ---------------------------------------------------------------------------
#
# These fixtures exercise the bypass the old checker had. It listed names from
# the central directory and extracted by name with unzip. A streaming extractor
# such as bsdtar reads local headers, so the two can see different bytes. The
# new reader requires both headers to agree and every local entry to be listed.

# A good stored entry with a data descriptor (flag bit 3), as ditto writes.
cat > "$work/spec-descriptor" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|8|0|1|1||
EOF
raw_zip_spec "$work/descriptor.ipa" "$work/spec-descriptor"
run --expected-version 0.1.0 --ipa "$work/descriptor.ipa"
expect_status 0 "a stored entry with a matching data descriptor passes"
expect_text "CFBundleShortVersionString is 0.1.0" "the descriptor entry is read"

# A descriptor whose CRC disagrees with the central directory.
cp "$work/descriptor.ipa" "$work/descriptor-bad.ipa"
dsize=$(wc -c < "$work/p/good.xml" | tr -d ' ')
dname=Payload/A.app/Info.plist
patch_le32 "$work/descriptor-bad.ipa" $((30 + ${#dname} + dsize + 4)) 0
run --expected-version 0.1.0 --ipa "$work/descriptor-bad.ipa"
expect_status 1 "a mismatched data descriptor fails"
expect_text "data descriptor CRC differs" "the descriptor mismatch is named"

# A descriptor entry must keep zero sizes in the local header.
cp "$work/descriptor.ipa" "$work/descriptor-size.ipa"
patch_le32 "$work/descriptor-size.ipa" 18 "$dsize"
run --expected-version 0.1.0 --ipa "$work/descriptor-size.ipa"
expect_status 1 "a descriptor entry with local sizes fails"
expect_text "must have zero sizes" "the nonzero local descriptor size is named"

# Local flags, method, and sizes must equal the central directory.
raw_zip "$work/locflags.ipa" "Payload/A.app/Info.plist"
patch_le16 "$work/locflags.ipa" 6 2048
run --expected-version 0.1.0 --ipa "$work/locflags.ipa"
expect_status 1 "a local flag mismatch fails"
expect_text "local flags differ from the central directory" "the flag mismatch is named"

raw_zip "$work/locmethod.ipa" "Payload/A.app/Info.plist"
patch_le16 "$work/locmethod.ipa" 8 8
run --expected-version 0.1.0 --ipa "$work/locmethod.ipa"
expect_status 1 "a local method mismatch fails"
expect_text "local method differs from the central directory" "the method mismatch is named"

raw_zip "$work/locsize.ipa" "Payload/A.app/Info.plist"
patch_le32 "$work/locsize.ipa" 18 1
run --expected-version 0.1.0 --ipa "$work/locsize.ipa"
expect_status 1 "a local size mismatch fails"
expect_text "local compressed size differs from the central directory" "the size mismatch is named"

# An unsupported general-purpose flag in the central directory.
cat > "$work/spec-flag" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|16|0|1|1||
EOF
raw_zip_spec "$work/flag.ipa" "$work/spec-flag"
run --expected-version 0.1.0 --ipa "$work/flag.ipa"
expect_status 1 "an unsupported general-purpose flag fails"
expect_text "unsupported general-purpose flag" "the unsupported flag is named"

# Local name says B, central directory says A. A central-only reader sees A.
cat > "$work/spec-mismatch" <<EOF
Payload/B.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|0|0|1|1||
EOF
raw_zip_spec "$work/mismatch.ipa" "$work/spec-mismatch"
run --expected-version 0.1.0 --ipa "$work/mismatch.ipa"
expect_status 1 "a central and local name mismatch fails"
expect_text "the local name differs from the central directory" "the mismatch is named"
if command -v bsdtar >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
  if ! cat "$work/mismatch.ipa" | bsdtar -tf - 2>/dev/null | grep '^Payload/B.app/Info.plist$' >/dev/null; then
    fail "streaming bsdtar did not read the local header name from the mismatch fixture"
  fi
  if ! unzip -Z1 "$work/mismatch.ipa" 2>/dev/null | grep '^Payload/A.app/Info.plist$' >/dev/null; then
    fail "unzip did not read the central-directory name from the mismatch fixture"
  fi
else
  echo "note: bsdtar or unzip is unavailable; the header disagreement cross-check is skipped" >&2
fi

# A local-only entry after the listed one. The old checker read only the central
# entry (good 0.1.0); a streaming extractor reads both and the old plist wins.
cat > "$work/spec-localonly" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|0|0|1|1||
Payload/A.app/Info.plist||$work/p/old.xml|0100644|0|0|1|0||
EOF
raw_zip_spec "$work/localonly.ipa" "$work/spec-localonly"
run --expected-version 0.1.0 --ipa "$work/localonly.ipa"
expect_status 1 "a local-only entry fails"
expect_text "the archive holds local data that the central directory does not list" "the local-only data is named"
if command -v bsdtar >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
  bcount=$(cat "$work/localonly.ipa" | bsdtar -tf - 2>/dev/null | grep -c '^Payload/A.app/Info.plist$' || true)
  ucount=$(unzip -Z1 "$work/localonly.ipa" 2>/dev/null | grep -c '^Payload/A.app/Info.plist$' || true)
  [ "$bcount" -eq 2 ] || fail "streaming bsdtar did not see both local headers in the local-only fixture (got $bcount)"
  [ "$ucount" -eq 1 ] || fail "unzip did not see one central entry in the local-only fixture (got $ucount)"
  # Streaming extraction writes the last local entry over the first. The old
  # checker read only the central entry (0.1.0); a stream sees 1.0.
  lx="$work/localonly-out"
  mkdir -p "$lx"
  (cd "$lx" && cat "$work/localonly.ipa" | bsdtar -xf - 2>/dev/null)
  if ! grep -q '<string>1.0</string>' "$lx/Payload/A.app/Info.plist" 2>/dev/null; then
    fail "streaming bsdtar did not extract the local-only old plist"
  fi
else
  echo "note: bsdtar or unzip is unavailable; the local-only cross-check is skipped" >&2
fi

# A NUL in a name must not terminate the name early.
raw_zip "$work/nulname.ipa" 'Payload/A.app/Info.plist\000'
run --expected-version 0.1.0 --ipa "$work/nulname.ipa"
expect_status 1 "a NUL in an entry name fails"
expect_text "byte outside the safe printable ASCII set" "the NUL is named"

# ZIP64 in any form is refused.
raw_zip "$work/zip64.ipa" "Payload/A.app/Info.plist"
size=$(wc -c < "$work/zip64.ipa" | tr -d ' ')
patch_le16 "$work/zip64.ipa" $((size - 22 + 8)) 65535
patch_le16 "$work/zip64.ipa" $((size - 22 + 10)) 65535
run --expected-version 0.1.0 --ipa "$work/zip64.ipa"
expect_status 1 "a ZIP64 end record fails"
expect_text "ZIP64 is not supported" "ZIP64 is named"

cat > "$work/spec-zip64extra" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|0|0|1|1||010008000000000000000000
EOF
raw_zip_spec "$work/zip64extra.ipa" "$work/spec-zip64extra"
run --expected-version 0.1.0 --ipa "$work/zip64extra.ipa"
expect_status 1 "a ZIP64 extra field fails"
expect_text "ZIP64 extra field is not supported" "the ZIP64 extra field is named"

cat > "$work/spec-unknown-extra" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|0|0|1|1||34120000
EOF
raw_zip_spec "$work/unknown-extra.ipa" "$work/spec-unknown-extra"
run --expected-version 0.1.0 --ipa "$work/unknown-extra.ipa"
expect_status 1 "an unknown extra field fails"
expect_text "unknown extra field is not supported" "the unknown extra field is named"

# Encryption and unsupported compression.
cat > "$work/spec-encrypted" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|1|0|1|1||
EOF
raw_zip_spec "$work/encrypted.ipa" "$work/spec-encrypted"
run --expected-version 0.1.0 --ipa "$work/encrypted.ipa"
expect_status 1 "an encrypted entry fails"
expect_text "an encrypted entry is not supported" "encryption is named"

cat > "$work/spec-method" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0100644|0|12|1|1||
EOF
raw_zip_spec "$work/method.ipa" "$work/spec-method"
run --expected-version 0.1.0 --ipa "$work/method.ipa"
expect_status 1 "an unsupported compression method fails"
expect_text "unsupported compression method" "the method is named"

# Special file types and a name/type mismatch.
cat > "$work/spec-symlink" <<EOF
Payload/A.app/Info.plist|Payload/A.app/Info.plist|$work/p/good.xml|0120777|0|0|1|1||
EOF
raw_zip_spec "$work/raw-symlink.ipa" "$work/spec-symlink"
run --expected-version 0.1.0 --ipa "$work/raw-symlink.ipa"
expect_status 1 "a raw symbolic link fails"
expect_text "special file type" "the special type is named"

cat > "$work/spec-dirmismatch" <<EOF
Payload/A.app/|Payload/A.app/||0100644|0|0|1|1||
EOF
raw_zip_spec "$work/dirmismatch.ipa" "$work/spec-dirmismatch"
run --expected-version 0.1.0 --ipa "$work/dirmismatch.ipa"
expect_status 1 "a directory name with a regular-file mode fails"
expect_text "file type disagree" "the directory mismatch is named"

# Windows aliases: trailing dots and spaces, drive letters, reserved names.
for badname in \
  'Payload/A.app/Info.plist.' \
  'Payload/A.app/Info.plist ' \
  'Payload/C:/A.app/Info.plist' \
  'Payload/A.app/CON' \
  'Payload/A.app/LPT1.txt'
do
  raw_zip "$work/alias.ipa" "$badname"
  run --expected-version 0.1.0 --ipa "$work/alias.ipa"
  expect_status 1 "Windows alias $badname fails"
done
raw_zip "$work/alias.ipa" 'Payload/A.app/Info.plist.'
run --expected-version 0.1.0 --ipa "$work/alias.ipa"
expect_text "component ending with a dot" "the trailing dot is named"
raw_zip "$work/alias.ipa" 'Payload/A.app/Info.plist '
run --expected-version 0.1.0 --ipa "$work/alias.ipa"
expect_text "leading or trailing space" "the trailing space is named"
raw_zip "$work/alias.ipa" 'Payload/C:/A.app/Info.plist'
run --expected-version 0.1.0 --ipa "$work/alias.ipa"
expect_text "colon or drive letter" "the drive letter is named"
raw_zip "$work/alias.ipa" 'Payload/A.app/CON'
run --expected-version 0.1.0 --ipa "$work/alias.ipa"
expect_text "Windows reserved device name" "the reserved name is named"

# A path with too many components is refused before the prefix map grows.
deep=Payload/A.app
i=0
while [ "$i" -lt 65 ]; do
  deep="$deep/a"
  i=$((i + 1))
done
deep="$deep/Info.plist"
raw_zip "$work/deep.ipa" "$deep"
run --expected-version 0.1.0 --ipa "$work/deep.ipa"
expect_status 1 "a path with too many components fails"
expect_text "more than 64 path components" "the component bound is named"

# An archive comment is not needed by a release artifact and is refused.
raw_zip "$work/comment.ipa" "Payload/A.app/Info.plist"
size=$(wc -c < "$work/comment.ipa" | tr -d ' ')
printf 'note' >> "$work/comment.ipa"
patch_le16 "$work/comment.ipa" $((size - 22 + 20)) 4
run --expected-version 0.1.0 --ipa "$work/comment.ipa"
expect_status 1 "an archive comment fails"
expect_text "archive comment is not supported" "the archive comment is named"

# A central directory that does not end at the end record.
raw_zip "$work/gap.ipa" "Payload/A.app/Info.plist"
size=$(wc -c < "$work/gap.ipa" | tr -d ' ')
patch_le32 "$work/gap.ipa" $((size - 22 + 16)) 1
run --expected-version 0.1.0 --ipa "$work/gap.ipa"
expect_status 1 "a central directory offset gap fails"
expect_text "does not end at the end-of-central-directory record" "the gap is named"

# ---------------------------------------------------------------------------
# Strict XML plist reading
# ---------------------------------------------------------------------------

# xml_body FILE BODY: a plist around BODY, which holds top-level dictionary content.
xml_body() {
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n%s\n</dict>\n</plist>\n' "$2" > "$1"
}

# xml_case NAME EXPECT_STATUS BODY MESSAGE
xml_case() {
  xml_body "$work/p/$1.xml" "$3"
  make_ipa "$work/$1.ipa" "$work/p/$1.xml"
  run --expected-version 0.1.0 --ipa "$work/$1.ipa"
  expect_status "$2" "xml plist case $1"
  [ -z "$4" ] || expect_text "$4" "xml plist case $1 message"
}

V='<key>CFBundleShortVersionString</key><string>0.1.0</string>'
xml_case ok-inline 0 "$V" "CFBundleShortVersionString is 0.1.0"
xml_case ok-spaced 0 "<key>CFBundleShortVersionString</key>   <string>0.1.0</string>   <key>CFBundleVersion</key>
	<string>7</string>" "CFBundleVersion 7"
xml_case ok-comment-between 0 "<!-- a note --><key>CFBundleShortVersionString</key><!-- x --><string>0.1.0</string>" "is 0.1.0"
xml_case ok-comment-multiline 0 "<!-- one
<key>CFBundleShortVersionString</key>
<string>9.9.9</string>
-->$V" "is 0.1.0"
xml_case ok-selfclose-empty 0 "<key>Other</key><dict/><key>List</key><array/><key>S</key><string/>$V" "is 0.1.0"
xml_case ok-booleans 0 "<key>B</key><true/><key>C</key><false/>$V" "is 0.1.0"

# A commented-out key is not a key.
xml_case comment-only 1 "<!-- $V -->" "cannot read CFBundleShortVersionString"
xml_case comment-lt 1 "<!-- <key>CFBundleShortVersionString</key><string>0.1.0</string> -->" "cannot read CFBundleShortVersionString"
# A comment cannot hide a duplicate from the reader, and a duplicate still fails.
xml_case dup 1 "$V<key>CFBundleShortVersionString</key><string>0.1.0</string>" "appears more than once"
xml_case dup-differs 1 "$V<key>CFBundleShortVersionString</key><string>0.2.0</string>" "appears more than once"
xml_case dup-after-comment 1 "$V<!-- c --><key>CFBundleShortVersionString</key><string>0.2.0</string>" "appears more than once"
xml_case dup-nonstring 1 "$V<key>CFBundleShortVersionString</key><integer>3</integer>" "appears more than once"
# Two different readings of whitespace: refuse both.
xml_case key-padded 1 "<key> CFBundleShortVersionString </key><string>0.1.0</string>" "surrounding whitespace"
xml_case key-padded-dup 1 "$V<key> CFBundleShortVersionString</key><string>0.2.0</string>" "surrounding whitespace"
xml_case value-padded 1 "<key>CFBundleShortVersionString</key><string> 0.1.0 </string>" "expected 0.1.0"
xml_case value-newline 1 "<key>CFBundleShortVersionString</key><string>
0.1.0
</string>" "expected 0.1.0"
# Entities and CDATA can spell a name or a value the reader would not match.
xml_case key-entity 1 "$V<key>CFBundleShort&#86;ersionString</key><string>0.2.0</string>" "entity"
xml_case value-entity 1 "<key>CFBundleShortVersionString</key><string>0.1&#46;0</string>" "expected 0.1.0"
xml_case cdata 1 "<key>CFBundleShortVersionString</key><string><![CDATA[0.1.0]]></string>" "CDATA"
xml_case comment-in-string 1 "<key>CFBundleShortVersionString</key><string>0.1.<!-- x -->0</string>" "comment inside"
xml_case key-control 1 "$(printf '<key>CFBundleShortVersionString\001</key><string>0.1.0</string>')" "control character"
xml_case value-control 1 "$(printf '<key>CFBundleShortVersionString</key><string>0.1.0\001</string>')" "control character"
xml_case stray-text 1 "stray $V" "text outside"
xml_case stray-text-after 1 "$V trailing" "text outside"
xml_case key-no-value 1 "$V<key>Other</key>" "no value"
xml_case two-keys 1 "<key>A</key><key>CFBundleShortVersionString</key><string>0.1.0</string>" "out of place"
xml_case value-no-key 1 "<string>x</string>$V" "no key"
xml_case unknown-element 1 "<key>A</key><foo/>$V" "unknown element"
xml_case unbalanced 1 "<key>A</key><dict>$V" "unbalanced"
xml_case attr 1 "<key a=\"b\">CFBundleShortVersionString</key><string>0.1.0</string>" "attribute"
xml_case nested-array-key 1 "<key>A</array></key>$V" ""

# Whole-document problems.
for plist_attrs in 'version="2.0"' "version='2.0'" 'version="1.0" extra="yes"' 'extra="yes" version="1.0"' 'version="1.0" version="1.0"' 'version="1.0" version="2.0"' ''; do
  printf '<?xml version="1.0"?><plist %s><dict>%s</dict></plist>\n' "$plist_attrs" "$V" > "$work/p/plist-attrs.xml"
  make_ipa "$work/plist-attrs.ipa" "$work/p/plist-attrs.xml"
  run --expected-version 0.1.0 --ipa "$work/plist-attrs.ipa"
  expect_status 1 "an invalid plist version attribute fails"
  expect_text "plist version attribute is invalid" "the plist attribute failure is named"
done
run --allow-unverified --expected-version 0.1.0 --ipa "$work/plist-attrs.ipa"
expect_status 1 "allow-unverified does not excuse a missing plist version attribute"
printf "<?xml version=\"1.0\"?><plist version='1.0'><dict>%s</dict></plist>\n" "$V" > "$work/p/plist-single-quote.xml"
make_ipa "$work/plist-single-quote.ipa" "$work/p/plist-single-quote.xml"
run --expected-version 0.1.0 --ipa "$work/plist-single-quote.ipa"
expect_status 0 "a single-quoted plist version is accepted"
printf '<?xml version="1.0"?><plist\n\tversion = "1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/plist-spaced-version.xml"
make_ipa "$work/plist-spaced-version.ipa" "$work/p/plist-spaced-version.xml"
run --expected-version 0.1.0 --ipa "$work/plist-spaced-version.ipa"
expect_status 0 "whitespace around the plist version attribute is accepted"

printf '<?xml version="1.0"?>\n<plist version="1.0"><array><string>x</string></array></plist>\n' > "$work/p/array-root.xml"
make_ipa "$work/array-root.ipa" "$work/p/array-root.xml"
run --expected-version 0.1.0 --ipa "$work/array-root.ipa"
expect_status 1 "an array at the top level fails"
expect_text "not a dictionary" "the array root is named"

printf '<?xml version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist><plist version="1.0"><dict>%s</dict></plist>\n' "$V" "$V" > "$work/p/two-roots.xml"
make_ipa "$work/two-roots.ipa" "$work/p/two-roots.xml"
run --expected-version 0.1.0 --ipa "$work/two-roots.ipa"
expect_status 1 "two plist elements fail"

printf '<?xml version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n<dict>%s</dict>\n' "$V" "$V" > "$work/p/after-root.xml"
make_ipa "$work/after-root.ipa" "$work/p/after-root.xml"
run --expected-version 0.1.0 --ipa "$work/after-root.ipa"
expect_status 1 "an element after the plist element fails"

printf '<?xml version="1.0"?>\n<!DOCTYPE plist [<!ENTITY v "0.1.0">]>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/subset.xml"
make_ipa "$work/subset.ipa" "$work/p/subset.xml"
run --expected-version 0.1.0 --ipa "$work/subset.ipa"
expect_status 1 "a DOCTYPE internal subset fails"
expect_text "internal subset" "the internal subset is named"

printf '<?xml version="1.0" encoding="UTF-16"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/enc.xml"
make_ipa "$work/enc.ipa" "$work/p/enc.xml"
run --expected-version 0.1.0 --ipa "$work/enc.ipa"
expect_status 1 "a UTF-16 declaration on UTF-8 text fails"
expect_text "encoding other than UTF-8" "the encoding is named"

printf '<?xml version="1.0" encoding="utf-8"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/enc8.xml"
make_ipa "$work/enc8.ipa" "$work/p/enc8.xml"
run --expected-version 0.1.0 --ipa "$work/enc8.ipa"
expect_status 0 "a lower-case utf-8 declaration passes"

# XML declaration rules: it must be first, appear once, and name version 1.0.
printf '<!-- note --><?xml version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/decl-late.xml"
make_ipa "$work/decl-late.ipa" "$work/p/decl-late.xml"
run --expected-version 0.1.0 --ipa "$work/decl-late.ipa"
expect_status 1 "an XML declaration after a comment fails"
expect_text "XML declaration is not first" "the late declaration is named"

printf '<?xml version="1.0"?><?xml version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/decl-two.xml"
make_ipa "$work/decl-two.ipa" "$work/p/decl-two.xml"
run --expected-version 0.1.0 --ipa "$work/decl-two.ipa"
expect_status 1 "a second XML declaration fails"
expect_text "more than one XML declaration" "the second declaration is named"

printf '<?xml version="2.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/decl-version.xml"
make_ipa "$work/decl-version.ipa" "$work/p/decl-version.xml"
run --expected-version 0.1.0 --ipa "$work/decl-version.ipa"
expect_status 1 "an XML declaration without version 1.0 fails"
expect_text "must name version 1.0" "the declaration version is named"

printf '<?xml encoding="UTF-8"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/decl-noversion.xml"
make_ipa "$work/decl-noversion.ipa" "$work/p/decl-noversion.xml"
run --expected-version 0.1.0 --ipa "$work/decl-noversion.ipa"
expect_status 1 "an XML declaration without a version fails"

printf '<?xml version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/decl-noenc.xml"
make_ipa "$work/decl-noenc.ipa" "$work/p/decl-noenc.xml"
run --expected-version 0.1.0 --ipa "$work/decl-noenc.ipa"
expect_status 0 "an XML declaration without an encoding passes"

printf '<?build note?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/pi-before.xml"
make_ipa "$work/pi-before.ipa" "$work/p/pi-before.xml"
run --expected-version 0.1.0 --ipa "$work/pi-before.ipa"
expect_status 0 "a processing instruction before the plist is skipped"

printf '<?build encoding="ISO-8859-1"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/pi-encoding.xml"
make_ipa "$work/pi-encoding.ipa" "$work/p/pi-encoding.xml"
run --expected-version 0.1.0 --ipa "$work/pi-encoding.ipa"
expect_status 0 "an encoding word in a processing instruction is not a declaration"

printf '<?XML version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/decl-upper.xml"
make_ipa "$work/decl-upper.ipa" "$work/p/decl-upper.xml"
run --expected-version 0.1.0 --ipa "$work/decl-upper.ipa"
expect_status 1 "an upper-case XML declaration fails"
expect_text "malformed XML declaration" "the malformed declaration is named"

printf '<?xml-stylesheet type="text/xsl"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/pi-xml-stylesheet.xml"
make_ipa "$work/pi-xml-stylesheet.ipa" "$work/p/pi-xml-stylesheet.xml"
run --expected-version 0.1.0 --ipa "$work/pi-xml-stylesheet.ipa"
expect_status 0 "an xml-stylesheet processing instruction is not a declaration"

printf '<?xml version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n<!-- never closed' "$V" > "$work/p/open-comment.xml"
make_ipa "$work/open-comment.ipa" "$work/p/open-comment.xml"
run --expected-version 0.1.0 --ipa "$work/open-comment.ipa"
expect_status 1 "an unterminated comment fails"

printf '\357\273\277<?xml version="1.0"?>\n<plist version="1.0"><dict>%s</dict></plist>\n' "$V" > "$work/p/bom.xml"
make_ipa "$work/bom.ipa" "$work/p/bom.xml"
run --expected-version 0.1.0 --ipa "$work/bom.ipa"
expect_status 1 "a UTF-8 byte order mark fails closed"

# UTF-16 text with a duplicate key. The reader cannot decode it and must fail.
xml_body "$work/p/dup16.xml" "$V<key>CFBundleShortVersionString</key><string>0.2.0</string>"
if command -v iconv >/dev/null 2>&1 &&
   iconv -f UTF-8 -t UTF-16LE "$work/p/dup16.xml" > "$work/p/dup16le.xml" 2>/dev/null &&
   { printf '\377\376'; cat "$work/p/dup16le.xml"; } > "$work/p/dup16bom.xml" &&
   iconv -f UTF-8 -t UTF-16BE "$work/p/dup16.xml" > "$work/p/dup16be.xml" 2>/dev/null; then
  for v in dup16le dup16bom dup16be; do
    make_ipa "$work/$v.ipa" "$work/p/$v.xml"
    run --expected-version 0.1.0 --ipa "$work/$v.ipa"
    expect_status 1 "UTF-16 plist $v fails"
    expect_text "UTF-16 or UTF-32 text is not read" "UTF-16 plist $v is named"
  done
  xml_body "$work/p/ok16.xml" "$V"
  iconv -f UTF-8 -t UTF-16LE "$work/p/ok16.xml" > "$work/p/ok16le.xml"
  make_ipa "$work/ok16le.ipa" "$work/p/ok16le.xml"
  run --expected-version 0.1.0 --ipa "$work/ok16le.ipa"
  expect_status 1 "a valid UTF-16 plist is refused, not guessed"
else
  # No iconv: write UTF-16LE text by hand.
  printf "\377\376<\000p\000l\000i\000s\000t\000>\000" > "$work/p/dup16nul.xml"
  make_ipa "$work/dup16nul.ipa" "$work/p/dup16nul.xml"
  run --expected-version 0.1.0 --ipa "$work/dup16nul.ipa"
  expect_status 1 "a plist with NUL bytes fails"
  expect_text "UTF-16 or UTF-32 text is not read" "the NUL bytes are named"
fi

# A NUL inside UTF-8 text fails too.
{ cat "$work/p/good.xml"; printf '\000'; } > "$work/p/nul.xml"
make_ipa "$work/nul.ipa" "$work/p/nul.xml"
run --expected-version 0.1.0 --ipa "$work/nul.ipa"
expect_status 1 "a NUL byte in a text plist fails"

# A hostile element name in the reason must not reach the log raw.
xml_case hostile-element 1 "$(printf "<key>A</key><b\033[31mad/>")$V" ""
if printf '%s' "$out" | grep "$(printf '\033')" >/dev/null; then
  fail "an escape character from an element name reached the output"
fi

# ---------------------------------------------------------------------------
# Strict binary plist reading
# ---------------------------------------------------------------------------

bin_plist "$work/p/b-dup-u.bin" CFBundleShortVersionString 0.1.0 u:CFBundleShortVersionString 0.2.0
make_ipa "$work/b-dup-u.ipa" "$work/p/b-dup-u.bin"
run --expected-version 0.1.0 --ipa "$work/b-dup-u.ipa"
expect_status 1 "a UTF-16 duplicate key in a binary plist fails"
expect_text "appears more than once" "the UTF-16 duplicate is named"

bin_plist "$work/p/b-dup-u2.bin" u:CFBundleShortVersionString 0.2.0 CFBundleShortVersionString 0.1.0
make_ipa "$work/b-dup-u2.ipa" "$work/p/b-dup-u2.bin"
run --expected-version 0.1.0 --ipa "$work/b-dup-u2.ipa"
expect_status 1 "a UTF-16 duplicate key listed first fails"

bin_plist "$work/p/b-dup-8.bin" 8:CFBundleShortVersionString 0.2.0 CFBundleShortVersionString 0.1.0
make_ipa "$work/b-dup-8.ipa" "$work/p/b-dup-8.bin"
run --expected-version 0.1.0 --ipa "$work/b-dup-8.ipa"
expect_status 1 "a UTF-8 duplicate key in a binary plist fails"

bin_plist "$work/p/b-u-only.bin" u:CFBundleShortVersionString 0.1.0
make_ipa "$work/b-u-only.ipa" "$work/p/b-u-only.bin"
run --expected-version 0.1.0 --ipa "$work/b-u-only.ipa"
expect_status 0 "a single UTF-16 key with a matching value passes"

bin_plist "$work/p/b-u-val.bin" CFBundleShortVersionString u:0.1.0
make_ipa "$work/b-u-val.ipa" "$work/p/b-u-val.bin"
run --expected-version 0.1.0 --ipa "$work/b-u-val.ipa"
expect_status 0 "a UTF-16 string value that matches passes"

bin_plist "$work/p/b-8-val.bin" CFBundleShortVersionString 8:0.2.0
make_ipa "$work/b-8-val.ipa" "$work/p/b-8-val.bin"
run --expected-version 0.1.0 --ipa "$work/b-8-val.ipa"
expect_status 1 "a UTF-8 string value that differs fails"
expect_text "UTF-8 binary string is unsupported" "the UTF-8 value is rejected"

{ printf 'bplist15'; tail -c +9 "$work/p/good.bin"; } > "$work/p/b-ver.bin"
make_ipa "$work/b-ver.ipa" "$work/p/b-ver.bin"
run --expected-version 0.1.0 --ipa "$work/b-ver.ipa"
expect_status 1 "an unsupported binary plist version fails"
expect_text "unsupported binary plist version" "the version is named"

# A key object that is not a string. Turn the first key reference of the
# generated plist into a reference to the offset-table-free dictionary object
# itself (object 0), which is not a string.
bin_plist "$work/p/b-nonstr.bin" CFBundleShortVersionString 0.1.0
{ head -c 9 "$work/p/b-nonstr.bin"; printf '\000'; tail -c +11 "$work/p/b-nonstr.bin"; } > "$work/p/b-nonstr2.bin"
make_ipa "$work/b-nonstr.ipa" "$work/p/b-nonstr2.bin"
run --expected-version 0.1.0 --ipa "$work/b-nonstr.ipa"
expect_status 1 "a dictionary key that is not a string fails"
expect_text "not a string" "the non-string key is named"

# ---------------------------------------------------------------------------
# The summary prints after a failure
# ---------------------------------------------------------------------------

# A name rule failure in one archive must not stop the run. Before the fix the
# nonzero return from the archive check aborted the script under set -e.
make_macho "$work/bin-with-text.bin" text
cscount=$(mktemp -d "$work/cont.XXXXXX")
raw_zip "$cscount/HotspotShade-iOS-unsigned.ipa" "Payload/./A.app/Info.plist"
raw_zip "$cscount/HotspotShade-unsigned.zip" "HotspotShade.app/../x"
cp "$work/bin-with-text.bin" "$cscount/hotspotshade-macos-arm64.bin"
run --expected-version 0.1.0 --tag v0.1.0 --artifacts "$cscount"
expect_status 1 "two unsafe archives fail"
expect_text "FAIL  HotspotShade-iOS-unsigned.ipa: an entry name has a dot or parent path component" "the IPA failure prints"
expect_text "FAIL  HotspotShade-unsigned.zip: an entry name has a dot or parent path component" "the zip failure prints"
expect_text "UNVERIFIED  hotspotshade-macos-arm64.bin" "the binary is still checked after two failures"
expect_text "Summary: 2 passed, 1 unverified, 2 failed" "the summary counts every result"
expect_text "The artifact version check failed." "the closing line prints"

# Each single-file option continues too: a bad zip before a good binary.
run --expected-version 0.1.0 --mac-zip "$cscount/HotspotShade-unsigned.zip" --mac-binary "$work/bin-with-text.bin"
expect_status 1 "a failed zip and a good binary fail"
expect_text "Summary:" "the summary prints after the zip fails"
expect_text "UNVERIFIED  bin-with-text.bin" "the binary line prints after the zip fails"

# A corrupt archive and an unreadable plist in one set both report.
printf 'not a zip' > "$cscount/HotspotShade-iOS-unsigned.ipa"
make_mac_zip "$cscount/HotspotShade-unsigned.zip" "$work/p/old.xml"
run --expected-version 0.1.0 --artifacts "$cscount"
expect_status 1 "a corrupt IPA and a stale zip fail"
expect_text "FAIL  HotspotShade-iOS-unsigned.ipa: the archive is too short to hold an end-of-central-directory record" "the corrupt IPA prints"
expect_text "FAIL  HotspotShade-unsigned.zip: CFBundleShortVersionString is 1.0, expected 0.1.0" "the stale zip prints"
expect_text "Summary:" "the summary prints after both"

# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

# A shim unzip that waits, so the signal arrives while the script is working.
mkdir -p "$work/slow"
cat > "$work/slow/unzip" <<SHIM
#!/bin/sh
sleep 2
exec "$real_unzip" "\$@"
SHIM
chmod +x "$work/slow/unzip"

# Background jobs ignore SIGINT unless job control is on.
set -m
for sig in TERM INT HUP; do
  case "$sig" in TERM) want=143 ;; INT) want=130 ;; HUP) want=129 ;; esac
  mkdir -p "$work/sigtmp.$sig"
  sigout="$work/sig.$sig.out"
  PATH="$work/slow:$PATH" TMPDIR="$work/sigtmp.$sig" sh "$checker" --expected-version 0.1.0 --ipa "$work/good-xml.ipa" > "$sigout" 2>&1 &
  pid=$!
  # Wait until the script created its work directory, then signal it.
  waited=0
  while [ -z "$(ls "$work/sigtmp.$sig" 2>/dev/null)" ] && [ "$waited" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  kill -"$sig" "$pid" 2>/dev/null || true
  sigstatus=0
  wait "$pid" || sigstatus=$?
  checks=$((checks + 1))
  if [ "$sigstatus" -ne "$want" ]; then
    fail "SIG$sig should exit $want, got $sigstatus"
    sed 's/^/    /' "$sigout" >&2
  fi
  if grep -q '^Summary:' "$sigout"; then
    fail "the script kept running after SIG$sig"
  fi
  if [ -n "$(ls "$work/sigtmp.$sig" 2>/dev/null)" ]; then
    fail "SIG$sig left a temporary directory behind"
  fi
done
set +m

# The plist extraction must not read from the checker's stdin. A shim unzip
# records whether unzip -p received a line from the caller's standard input.
mkdir -p "$work/stdin-shim"
cat > "$work/stdin-shim/unzip" <<SHIM
#!/bin/sh
if [ "\$1" = "-p" ]; then
  if read -r line; then
    printf '%s\n' "\$line" > "$work/stdin-seen"
  fi
fi
exec "$real_unzip" "\$@"
SHIM
chmod +x "$work/stdin-shim/unzip"
rm -f "$work/stdin-seen"
status=0
out=$(printf 'secret\n' | PATH="$work/stdin-shim:$PATH" sh "$checker" --expected-version 0.1.0 --ipa "$work/good-xml.ipa" 2>&1) || status=$?
checks=$((checks + 1))
expect_status 0 "unzip stdin closure keeps the extraction working"
if [ -e "$work/stdin-seen" ]; then
  fail "unzip -p read from the checker's standard input"
fi

# ---------------------------------------------------------------------------
# macOS app zip
# ---------------------------------------------------------------------------

make_mac_zip "$work/good.zip" "$work/p/good.xml"
run --expected-version 0.1.0 --mac-zip "$work/good.zip"
expect_status 3 "a matching app zip leaves the engine unverified"
expect_text "PASS  good.zip: CFBundleShortVersionString is 0.1.0" "the app version is read"
expect_text "UNVERIFIED  good.zip: the bundled engine" "the engine is reported unverified"
run --expected-version 0.1.0 --allow-unverified --mac-zip "$work/good.zip"
expect_status 0 "--allow-unverified turns the unverified exit into 0"
expect_text "UNVERIFIED" "--allow-unverified still prints the unverified line"
expect_text "not a verified release" "--allow-unverified labels the zip result unverified"
if printf '%s\n' "$out" | grep -xF 'The artifact version check passed.' >/dev/null; then
  fail "--allow-unverified claimed a plain verified pass for the app zip"
fi

make_mac_zip "$work/good-bin.zip" "$work/p/good.bin"
run --expected-version 0.1.0 --mac-zip "$work/good-bin.zip"
expect_status 3 "an app zip with a binary plist and an engine is verified but for the engine"

# A bundled engine must itself be a valid arm64 Mach-O executable.
for v in x86 fat filetype short; do
  make_mac_zip "$work/engine-$v.zip" "$work/p/good.xml" with-engine "$v"
  run --expected-version 0.1.0 --mac-zip "$work/engine-$v.zip"
  expect_status 1 "an app zip with engine variant $v fails"
  run --expected-version 0.1.0 --allow-unverified --mac-zip "$work/engine-$v.zip"
  expect_status 1 "--allow-unverified does not excuse engine variant $v"
done

make_mac_zip "$work/noengine.zip" "$work/p/good.bin" no-engine
run --expected-version 0.1.0 --mac-zip "$work/noengine.zip"
expect_status 1 "an app zip with no bundled engine fails"
expect_text "FAIL  noengine.zip: the bundled engine Contents/Resources/bin/hotspotshade is missing" "the missing engine is named"
run --expected-version 0.1.0 --allow-unverified --mac-zip "$work/noengine.zip"
expect_status 1 "--allow-unverified does not excuse a missing engine"
reject_text "UNVERIFIED  noengine.zip" "no engine claim when the engine is missing"

# An engine under a different app name does not count.
d="$work/engname"; mkdir -p "$d/HotspotShade.app/Contents/Resources/bin" "$d/Other.app/Contents/Resources/bin"
cp "$work/p/good.xml" "$d/HotspotShade.app/Contents/Info.plist"
printf x > "$d/Other.app/Contents/Resources/bin/hotspotshade"
(cd "$d" && zip -qr "$work/engname.zip" HotspotShade.app Other.app)
run --expected-version 0.1.0 --mac-zip "$work/engname.zip"
expect_status 1 "two app bundles fail even when one holds an engine"

make_mac_zip "$work/old.zip" "$work/p/old.xml"
run --expected-version 0.1.0 --mac-zip "$work/old.zip"
expect_status 1 "an app zip that says 1.0 fails"

# ditto writes data descriptors and uses different local and central extra
# lengths. The official macOS app zip is built with ditto, so this path matters.
if command -v ditto >/dev/null 2>&1; then
  d="$work/ditto"; mkdir -p "$d/HotspotShade.app/Contents/Resources/bin"
  cp "$work/p/good.xml" "$d/HotspotShade.app/Contents/Info.plist"
  make_macho "$d/HotspotShade.app/Contents/Resources/bin/hotspotshade" text
  head -c 50000 /dev/zero | tr '\0' 'a' >> "$d/HotspotShade.app/Contents/Resources/bin/hotspotshade"
  (cd "$d" && ditto -c -k --keepParent HotspotShade.app "$work/ditto.zip")
  run --expected-version 0.1.0 --mac-zip "$work/ditto.zip"
  expect_status 3 "a ditto app zip with data descriptors passes"
  expect_text "CFBundleShortVersionString is 0.1.0" "the ditto plist is read"
  expect_text "UNVERIFIED" "the ditto engine is unverified"
else
  echo "note: ditto is unavailable; the data-descriptor app zip check is skipped" >&2
fi

# An app zip whose plist is at the wrong depth.
d="$work/macbad"; mkdir -p "$d/HotspotShade.app"
cp "$work/p/good.xml" "$d/HotspotShade.app/Info.plist"
(cd "$d" && zip -qr "$work/macbad.zip" HotspotShade.app)
run --expected-version 0.1.0 --mac-zip "$work/macbad.zip"
expect_status 1 "an app zip with no Contents/Info.plist fails"

# ---------------------------------------------------------------------------
# macOS binary: never fabricated
# ---------------------------------------------------------------------------

# A valid arm64 Mach-O that contains version text from a web asset must stay
# unverified. The text is not a version field.
make_macho "$work/bin-with-text.bin" text
run --expected-version 0.1.0 --mac-binary "$work/bin-with-text.bin"
expect_status 3 "a binary with embedded version text stays unverified"
expect_text "UNVERIFIED  bin-with-text.bin" "the binary is reported unverified"
reject_text "PASS  bin-with-text.bin" "no version claim for a binary"
run --expected-version 0.1.0 --allow-unverified --mac-binary "$work/bin-with-text.bin"
expect_status 0 "--allow-unverified accepts an unverified binary"
expect_text "not a verified release" "--allow-unverified labels the result unverified"
if printf '%s\n' "$out" | grep -xF 'The artifact version check passed.' >/dev/null; then
  fail "--allow-unverified claimed a plain verified pass"
fi

# A header alone does not establish even the load-command framing.
cp "$work/bin-with-text.bin" "$work/bin-bad-command.bin"
patch_le32 "$work/bin-bad-command.bin" 36 16
run --expected-version 0.1.0 --mac-binary "$work/bin-bad-command.bin"
expect_status 1 "a load command extending beyond sizeofcmds fails"
cp "$work/bin-with-text.bin" "$work/bin-zero-command.bin"
patch_le32 "$work/bin-zero-command.bin" 36 0
run --expected-version 0.1.0 --mac-binary "$work/bin-zero-command.bin"
expect_status 1 "a zero-length load command fails"

# A malformed or wrong-architecture binary fails even with --allow-unverified.
for v in x86 fat filetype short; do
  make_macho "$work/bin-$v.bin" "$v"
  run --expected-version 0.1.0 --mac-binary "$work/bin-$v.bin"
  expect_status 1 "binary variant $v fails"
  run --expected-version 0.1.0 --allow-unverified --mac-binary "$work/bin-$v.bin"
  expect_status 1 "--allow-unverified does not excuse binary variant $v"
done
printf 'not a Mach-O' > "$work/bin-garbage.bin"
run --expected-version 0.1.0 --allow-unverified --mac-binary "$work/bin-garbage.bin"
expect_status 1 "--allow-unverified does not excuse a non-Mach-O binary"

ln -s "$work/bin-with-text.bin" "$work/bin-link.bin"
run --expected-version 0.1.0 --mac-binary "$work/bin-link.bin"
expect_status 1 "a symlinked binary fails"
run --expected-version 0.1.0 --mac-binary "$work/missing.bin"
expect_status 1 "a missing binary fails"

# ---------------------------------------------------------------------------
# Directory mode, tag, expected version
# ---------------------------------------------------------------------------

set_dir="$work/set"
mkdir -p "$set_dir"
cp "$work/good-bin.ipa" "$set_dir/HotspotShade-iOS-unsigned.ipa"
cp "$work/good.zip" "$set_dir/HotspotShade-unsigned.zip"
cp "$work/bin-with-text.bin" "$set_dir/hotspotshade-macos-arm64.bin"
run --expected-version 0.1.0 --tag v0.1.0 --artifacts "$set_dir"
expect_status 3 "a complete matching set is unverified for the binaries only"
expect_text "PASS  tag v0.1.0 matches the expected version" "the tag matches"
expect_text "PASS  HotspotShade-iOS-unsigned.ipa: CFBundleShortVersionString is 0.1.0" "the set IPA passes"
expect_text "PASS  HotspotShade-unsigned.zip: CFBundleShortVersionString is 0.1.0" "the set app passes"
run --expected-version 0.1.0 --tag v0.1.0 --allow-unverified --artifacts "$set_dir"
expect_status 0 "a complete matching set passes with --allow-unverified"

run --expected-version 0.1.0 --tag v0.1.1 --artifacts "$set_dir"
expect_status 1 "a tag that does not match fails"
expect_text "does not equal v0.1.0" "the tag drift is named"

cp "$work/old.ipa" "$set_dir/HotspotShade-iOS-unsigned.ipa"
run --expected-version 0.1.0 --allow-unverified --artifacts "$set_dir"
expect_status 1 "a stale IPA in the set fails even with --allow-unverified"

rm "$set_dir/hotspotshade-macos-arm64.bin"
run --expected-version 0.1.0 --artifacts "$set_dir"
expect_status 1 "a set that lacks the binary fails"
expect_text "the release set is missing a regular file: hotspotshade-macos-arm64.bin" "the missing file is named"

run --expected-version 0.1.0 --artifacts "$work/no-such-dir"
expect_status 1 "a missing artifact directory fails"

# --repo-root reads rust/Cargo.toml.
mkdir -p "$work/repo/rust"
printf '[package]\nname = "hotspotshade"\nversion = "0.1.0"\n' > "$work/repo/rust/Cargo.toml"
run --repo-root "$work/repo" --ipa "$work/good-xml.ipa"
expect_status 0 "--repo-root supplies the version"
printf '[package.metadata.release]\nversion = "9.9.9"\n[package]\nname = "hotspotshade"\nversion = "0.1.0"\n' > "$work/repo/rust/Cargo.toml"
run --repo-root "$work/repo" --ipa "$work/good-xml.ipa"
expect_status 0 "--repo-root ignores a version outside the package table"
printf '[package]\nname = "hotspotshade"\nversion = "0.1.0"\nversion = "0.2.0"\n' > "$work/repo/rust/Cargo.toml"
run --repo-root "$work/repo" --ipa "$work/good-xml.ipa"
expect_status 2 "--repo-root rejects ambiguous package versions"
cat > "$work/repo/rust/Cargo.toml" <<'EOF'
[package]
version.workspace = true
description = """
version = "0.1.0"
"""
EOF
run --repo-root "$work/repo" --ipa "$work/good-xml.ipa"
expect_status 2 "--repo-root rejects a version inside a multiline string"
printf '[package]\nname = "hotspotshade"\nversion = "0.2.0"\n' > "$work/repo/rust/Cargo.toml"
run --repo-root "$work/repo" --ipa "$work/good-xml.ipa"
expect_status 1 "--repo-root with a different version fails the IPA"

# A hostile filename must not put control characters in the log.
cp "$work/good-xml.ipa" "$work/label"$'\033'"[31m.ipa"
run --expected-version 0.1.0 --ipa "$work/label"$'\033'"[31m.ipa"
expect_status 0 "an artifact with control characters in its name passes"
expect_text "label??31m.ipa" "the filename label is sanitized"
if printf '%s' "$out" | grep "$(printf '\033')" >/dev/null; then
  fail "a control character from a filename reached the output"
fi

# The output states the scope instead of implying identity or signing proof.
run --expected-version 0.1.0 --ipa "$work/good-xml.ipa"
expect_text "does not verify app identity" "the app identity scope is stated"

# Usage errors.
run --ipa "$work/good-xml.ipa"
expect_status 2 "no expected version is a usage error"
run --expected-version 0.1 --ipa "$work/good-xml.ipa"
expect_status 2 "a two-part expected version is a usage error"
run --expected-version 0.1.0
expect_status 2 "no artifact is a usage error"
run --expected-version 0.1.0 --artifacts "$set_dir" --ipa "$work/good-xml.ipa"
expect_status 2 "--artifacts with a single-file option is a usage error"
run --expected-version 0.1.0 --expected-version
expect_status 2 "a missing option value is a usage error"
run --expected-version 0.1.0 --bogus
expect_status 2 "an unknown option is a usage error"
run --repo-root "$work/none" --ipa "$work/good-xml.ipa"
expect_status 2 "an unreadable repo root is a usage error"

# Isolate this check from other concurrent runs using the shared TMPDIR.
mkdir "$work/cleanup-tmp"
TMPDIR="$work/cleanup-tmp" run --expected-version 0.1.0 --ipa "$work/good-xml.ipa"
expect_status 0 "the cleanup fixture itself passes"
if ! cleanup_entries=$(find "$work/cleanup-tmp" -mindepth 1 -print); then
  fail "cannot inspect the checker's temporary directory"
elif [ -n "$cleanup_entries" ]; then
  fail "the checker left a temporary directory behind"
fi

# ---------------------------------------------------------------------------
# Awk matrix
# ---------------------------------------------------------------------------
#
# Exercise bounded streaming on highly compressible data spanning many output chunks.
make_ipa "$work/large-deflate.ipa" "$work/p/good.xml"
mkdir -p "$work/large/Payload/HotspotProxy.app"
head -c 1048576 /dev/zero > "$work/large/Payload/HotspotProxy.app/large"
(cd "$work/large" && zip -q "$work/large-deflate.ipa" Payload/HotspotProxy.app/large)
run --expected-version 0.1.0 --ipa "$work/large-deflate.ipa"
expect_status 0 "a valid large deflate stream passes bounded verification"

# Build one valid raw deflate stream. Each negative fixture below changes one
# property from that baseline and keeps the other ZIP metadata consistent.
perl -MCompress::Raw::Zlib -e '
  use Compress::Raw::Zlib;
  local $/; my $data = <>;
  my ($d, $st) = Compress::Raw::Zlib::Deflate->new(-WindowBits => -15);
  $st == Z_OK or die; my ($part, $end) = ("", "");
  $d->deflate($data, $part) == Z_OK or die;
  $d->flush($end) == Z_OK or die;
  binmode STDOUT; print $part, $end;
' "$work/p/good.xml" > "$work/valid-deflate"
hname='Payload/HotspotProxy.app/Info.plist'
husize=$(wc -c < "$work/p/good.xml" | tr -d ' ')
hcrc=$(zip_crc_file "$work/p/good.xml")
make_deflate_ipa() {
  local output=$1 payload=$2 size cd
  size=$(wc -c < "$payload" | tr -d ' ')
  cd=$((30 + ${#hname} + size))
  printf '%s\n' "$hname|$hname|$payload||0|8|1|1||" > "$work/spec-deflate"
  raw_zip_spec "$output" "$work/spec-deflate"
  patch_le32 "$output" 14 "$hcrc"
  patch_le32 "$output" 22 "$husize"
  patch_le32 "$output" $((cd + 16)) "$hcrc"
  patch_le32 "$output" $((cd + 24)) "$husize"
}
make_deflate_ipa "$work/valid-deflate.ipa" "$work/valid-deflate"
run --expected-version 0.1.0 --ipa "$work/valid-deflate.ipa"
expect_status 0 "the valid deflate baseline passes"

# A verifier that fails silently must not be mistaken for a successful check.
original_checker=$checker
for stage in local data; do
  sed "s/^zip_check_${stage}() {$/zip_check_${stage}() { return 1;/" \
    "$original_checker" > "$work/silent-${stage}-checker.sh"
  checker="$work/silent-${stage}-checker.sh"
  run --expected-version 0.1.0 --ipa "$work/valid-deflate.ipa"
  expect_status 1 "a silently failing $stage verifier fails closed"
  if [ "$stage" = local ]; then
    expect_text "local header verifier failed without a reason" "silent local failure is reported"
  else
    expect_text "payload verifier failed without a reason" "silent payload failure is reported"
  fi
done
checker=$original_checker

# deflate_file INPUT OUTPUT: one complete raw deflate stream from INPUT.
deflate_file() {
  local input=$1 output=$2
  perl -MCompress::Raw::Zlib -e '
    use Compress::Raw::Zlib;
    local $/; my $data = <>;
    my ($d, $st) = Compress::Raw::Zlib::Deflate->new(-WindowBits => -15);
    $st == Z_OK or die; my ($part, $end) = ("", "");
    $d->deflate($data, $part) == Z_OK or die;
    $d->flush($end) == Z_OK or die;
    binmode STDOUT; print $part, $end;
  ' "$input" > "$output"
}

# append_local_header FILE NAME: append one complete stored local file header.
# A deflate member followed by real structure is a stronger hidden-entry fixture
# than a bare signature, because a checker that only looks for PK\003\004 would
# stop at the signature and miss the fields behind it.
append_local_header() {
  local file=$1 name=$2 nlen
  nlen=${#name}
  {
    printf 'PK\003\004'
    printf "$(le16 20)$(le16 0)$(le16 0)$(le16 0)$(le16 0)"
    printf "$(le32 0)$(le32 0)$(le32 0)"
    printf "$(le16 "$nlen")$(le16 0)"
    printf '%s' "$name"
  } >> "$file"
}

# A complete stream followed by an actual local-header signature must fail.
cp "$work/valid-deflate" "$work/hidden-deflate"
printf '\120\113\003\004hidden' >> "$work/hidden-deflate"
make_deflate_ipa "$work/hidden-deflate.ipa" "$work/hidden-deflate"
run --expected-version 0.1.0 --ipa "$work/hidden-deflate.ipa"
expect_status 1 "a deflate stream with a hidden trailing local-header signature fails"
expect_text "has trailing compressed bytes" "the hidden signature is named as trailing bytes"

# The same with a complete local header after the deflate stream, not only its
# four-byte signature. The full header includes version, flags, sizes, and name.
cp "$work/valid-deflate" "$work/hidden-full-header"
append_local_header "$work/hidden-full-header" 'Payload/HotspotProxy.app/hidden'
make_deflate_ipa "$work/hidden-full-header.ipa" "$work/hidden-full-header"
run --expected-version 0.1.0 --ipa "$work/hidden-full-header.ipa"
expect_status 1 "a deflate stream with a complete hidden local header fails"
expect_text "has trailing compressed bytes" "the complete hidden header is named as trailing bytes"

vsize=$(wc -c < "$work/valid-deflate" | tr -d ' ')
vcd=$((30 + ${#hname} + vsize))
head -c $((vsize - 1)) "$work/valid-deflate" > "$work/truncated-deflate"
make_deflate_ipa "$work/truncated-deflate.ipa" "$work/truncated-deflate"
run --expected-version 0.1.0 --ipa "$work/truncated-deflate.ipa"
expect_status 1 "a deflate stream missing its end fails"
expect_text "compressed stream did not end" "the missing stream end is named"
cp "$work/valid-deflate.ipa" "$work/bad-declared-size.ipa"
patch_le32 "$work/bad-declared-size.ipa" 22 $((husize - 1))
patch_le32 "$work/bad-declared-size.ipa" $((vcd + 24)) $((husize - 1))
run --expected-version 0.1.0 --ipa "$work/bad-declared-size.ipa"
expect_status 1 "a deflate entry with a false uncompressed size fails"
expect_text "exceeds declared size" "the smaller declared size is named"
cp "$work/valid-deflate.ipa" "$work/bad-declared-larger.ipa"
patch_le32 "$work/bad-declared-larger.ipa" 22 $((husize + 1))
patch_le32 "$work/bad-declared-larger.ipa" $((vcd + 24)) $((husize + 1))
run --expected-version 0.1.0 --ipa "$work/bad-declared-larger.ipa"
expect_status 1 "a deflate entry that declares more output than it holds fails"
expect_text "uncompressed size mismatch" "the larger declared size is named"
cp "$work/valid-deflate.ipa" "$work/bad-deflate-crc.ipa"
patch_le32 "$work/bad-deflate-crc.ipa" 14 0
patch_le32 "$work/bad-deflate-crc.ipa" $((vcd + 16)) 0
run --expected-version 0.1.0 --ipa "$work/bad-deflate-crc.ipa"
expect_status 1 "a valid deflate stream with a false CRC fails"
expect_text "CRC mismatch" "the false CRC is named"

# Corruption past the engine header must not escape the archive CRC check.
make_macho "$work/engine-fixture" ok
eplist='HotspotShade.app/Contents/Info.plist'
engine='HotspotShade.app/Contents/Resources/bin/hotspotshade'
printf '%s\n' "$eplist|$eplist|$work/p/good.xml||0|0|1|1||" "$engine|$engine|$work/engine-fixture||0|0|1|1||" > "$work/spec-engine"
raw_zip_spec "$work/bad-engine.zip" "$work/spec-engine"
engineoff=$((30 + ${#eplist} + husize + 30 + ${#engine} + 4000))
printf X | dd of="$work/bad-engine.zip" bs=1 seek="$engineoff" conv=notrunc 2>/dev/null
run --expected-version 0.1.0 --allow-unverified --mac-zip "$work/bad-engine.zip"
expect_status 1 "corruption beyond the bundled engine header fails"

# CRC applies to every member, including files unrelated to the version.
printf 'unrelated payload' > "$work/other-payload"
printf '%s\n' "Payload/HotspotProxy.app/Info.plist|Payload/HotspotProxy.app/Info.plist|$work/p/good.xml||0|0|1|1||" "Payload/HotspotProxy.app/other|Payload/HotspotProxy.app/other|$work/other-payload||0|0|1|1||" > "$work/spec-other"
raw_zip_spec "$work/bad-other.ipa" "$work/spec-other"
otheroff=$((30 + ${#hname} + husize + 30 + ${#hname} - 5))
printf X | dd of="$work/bad-other.ipa" bs=1 seek="$otheroff" conv=notrunc 2>/dev/null
run --expected-version 0.1.0 --ipa "$work/bad-other.ipa"
expect_status 1 "a corrupt unrelated stored entry fails"

# Check the deflate path for a member unrelated to the plist. The valid
# archive must pass before a single byte in that member is damaged.
other='Payload/HotspotProxy.app/other'
printf '%s\n' "$hname|$hname|$work/p/good.xml||0|0|1|1||" "$other|$other|$work/valid-deflate||0|8|1|1||" > "$work/spec-other-deflate"
raw_zip_spec "$work/other-deflate.ipa" "$work/spec-other-deflate"
otherlocal=$((30 + ${#hname} + husize))
othercentral=$((otherlocal + 30 + ${#other} + vsize + 46 + ${#hname}))
patch_le32 "$work/other-deflate.ipa" $((otherlocal + 14)) "$hcrc"
patch_le32 "$work/other-deflate.ipa" $((otherlocal + 22)) "$husize"
patch_le32 "$work/other-deflate.ipa" $((othercentral + 16)) "$hcrc"
patch_le32 "$work/other-deflate.ipa" $((othercentral + 24)) "$husize"
run --expected-version 0.1.0 --ipa "$work/other-deflate.ipa"
expect_status 0 "a valid unrelated deflate entry passes"
cp "$work/other-deflate.ipa" "$work/bad-other-deflate.ipa"
printf '\006' | dd of="$work/bad-other-deflate.ipa" bs=1 seek=$((otherlocal + 30 + ${#other})) conv=notrunc 2>/dev/null
run --expected-version 0.1.0 --ipa "$work/bad-other-deflate.ipa"
expect_status 1 "a corrupt unrelated deflate entry fails"
expect_text "has invalid compressed data" "the invalid unrelated deflate stream is named"

# These mutations target an unrelated member. Plist extraction cannot reject
# them, so each failure depends on validation of all archive payloads.
cp "$work/other-deflate.ipa" "$work/other-bad-size.ipa"
patch_le32 "$work/other-bad-size.ipa" $((otherlocal + 22)) $((husize - 1))
patch_le32 "$work/other-bad-size.ipa" $((othercentral + 24)) $((husize - 1))
run --expected-version 0.1.0 --ipa "$work/other-bad-size.ipa"
expect_status 1 "an unrelated deflate entry with a false size fails"
expect_text "exceeds declared size" "the smaller unrelated declared size is named"

cp "$work/other-deflate.ipa" "$work/other-bad-crc.ipa"
patch_le32 "$work/other-bad-crc.ipa" $((otherlocal + 14)) 0
patch_le32 "$work/other-bad-crc.ipa" $((othercentral + 16)) 0
run --expected-version 0.1.0 --ipa "$work/other-bad-crc.ipa"
expect_status 1 "an unrelated deflate entry with a false CRC fails"
expect_text "CRC mismatch" "the unrelated false CRC is named"

printf '%s\n' "$hname|$hname|$work/p/good.xml||0|0|1|1||" "$other|$other|$work/truncated-deflate||0|8|1|1||" > "$work/spec-other-truncated"
raw_zip_spec "$work/other-truncated.ipa" "$work/spec-other-truncated"
truncated_size=$((vsize - 1))
truncated_central=$((otherlocal + 30 + ${#other} + truncated_size + 46 + ${#hname}))
patch_le32 "$work/other-truncated.ipa" $((otherlocal + 14)) "$hcrc"
patch_le32 "$work/other-truncated.ipa" $((otherlocal + 22)) "$husize"
patch_le32 "$work/other-truncated.ipa" $((truncated_central + 16)) "$hcrc"
patch_le32 "$work/other-truncated.ipa" $((truncated_central + 24)) "$husize"
run --expected-version 0.1.0 --ipa "$work/other-truncated.ipa"
expect_status 1 "an unrelated deflate entry missing its end fails"
expect_text "compressed stream did not end" "the unrelated missing stream end is named"

# The payload verifier is required even when the metadata and plist are valid.
# A PATH without perl names the missing interpreter, not a module failure.
mkdir -p "$work/no-perl-path"
for tool in awk cut grep gzip head mktemp od rm sed sh sort tail tr unzip wc; do
  tool_path=$(command -v "$tool" 2>/dev/null || true)
  if [ -z "$tool_path" ]; then
    fail "the no-perl PATH fixture needs $tool"
    continue
  fi
  ln -sf "$tool_path" "$work/no-perl-path/$tool"
done
status=0
out=$(PATH="$work/no-perl-path" sh "$checker" --expected-version 0.1.0 --ipa "$work/good-xml.ipa" 2>&1) || status=$?
checks=$((checks + 1))
expect_status 1 "a missing Perl fails closed"
expect_text "the payload verifier is unavailable: perl is missing" "the missing interpreter is named"

# A present perl that cannot start is a separate failure from a missing module.
mkdir -p "$work/no-perl-run"
cat > "$work/no-perl-run/perl" <<'SHIM'
#!/bin/sh
exit 1
SHIM
chmod +x "$work/no-perl-run/perl"
status=0
out=$(PATH="$work/no-perl-run:$PATH" sh "$checker" --expected-version 0.1.0 --ipa "$work/good-xml.ipa" 2>&1) || status=$?
checks=$((checks + 1))
expect_status 1 "a Perl that cannot run fails closed"
expect_text "the payload verifier is unavailable: perl cannot run" "the unusable interpreter is named"

# Perl itself still works when the required module fails to load. This checks
# the dependency boundary separately from an unavailable Perl executable.
mkdir -p "$work/broken-module/Compress/Raw"
cat > "$work/broken-module/Compress/Raw/Zlib.pm" <<'BROKEN_MODULE'
die "injected zlib module load failure\n";
BROKEN_MODULE
PERL5LIB="$work/broken-module" perl -e 'exit 0' || fail "the module fixture must leave Perl usable"
if PERL5LIB="$work/broken-module" perl -MCompress::Raw::Zlib -e 'exit 0' 2>/dev/null; then
  fail "the module fixture did not prevent zlib loading"
fi
status=0
out=$(PERL5LIB="$work/broken-module" sh "$checker" --expected-version 0.1.0 --ipa "$work/good-xml.ipa" 2>&1) || status=$?
checks=$((checks + 1))
expect_status 1 "a failed zlib module load fails closed with working Perl"
expect_text "the payload verifier is unavailable: the Compress::Raw::Zlib module cannot load" "the failed module load is named"

# A valid stream whose expansion plus the plist exceeds the aggregate bound.
# Generate it in chunks, so the fixture itself never stores a GiB on disk.
perl -MCompress::Raw::Zlib -e '
  use Compress::Raw::Zlib qw(Z_OK crc32);
  my ($out, $crcfile) = @ARGV;
  open my $f, ">:raw", $out or die;
  my ($d, $status) = Compress::Raw::Zlib::Deflate->new(-WindowBits => -15);
  $status == Z_OK or die;
  my $chunk = "\0" x 65536; my $crc = 0;
  for (1..16384) {
    $crc = crc32($chunk, $crc);
    my $data = ""; $d->deflate($chunk, $data) == Z_OK or die;
    length($chunk) == 65536 or die "deflater consumed the fixture buffer";
    print $f $data or die;
  }
  my $tail = ""; $d->flush($tail) == Z_OK or die; print $f $tail or die;
  close $f or die;
  open my $c, ">", $crcfile or die; print $c $crc or die; close $c or die;
' "$work/gib-deflate" "$work/gib-crc"
gibsize=$(wc -c < "$work/gib-deflate" | tr -d ' ')
gibcrc=$(cat "$work/gib-crc")
printf '%s\n' "$hname|$hname|$work/p/good.xml||0|0|1|1||" "$other|$other|$work/gib-deflate||0|8|1|1||" > "$work/spec-gib"
raw_zip_spec "$work/aggregate-bound.ipa" "$work/spec-gib"
gibcentral=$((otherlocal + 30 + ${#other} + gibsize + 46 + ${#hname}))
patch_le32 "$work/aggregate-bound.ipa" $((otherlocal + 14)) "$gibcrc"
patch_le32 "$work/aggregate-bound.ipa" $((otherlocal + 22)) 1073741824
patch_le32 "$work/aggregate-bound.ipa" $((gibcentral + 16)) "$gibcrc"
patch_le32 "$work/aggregate-bound.ipa" $((gibcentral + 24)) 1073741824
run --expected-version 0.1.0 --ipa "$work/aggregate-bound.ipa"
expect_status 1 "valid streams exceeding the aggregate expansion bound fail"
expect_text "exceeds uncompressed data bound" "the aggregate bound failure is named"
# Prove the fixture is otherwise valid, so a different failure cannot hide a
# broken aggregate check. This copy is confined to the test work directory.
sed 's/\$total > 1073741824/\$total > 2147483648/' "$checker" > "$work/relaxed-checker.sh"
status=0
out=$(sh "$work/relaxed-checker.sh" --expected-version 0.1.0 --ipa "$work/aggregate-bound.ipa" 2>&1) || status=$?
checks=$((checks + 1))
expect_status 0 "the aggregate-bound fixture passes with a raised limit"

# The aggregate bound is a strict upper bound. Exactly the limit is accepted
# and one more declared byte is refused. Expanding a full GiB only to test one
# byte is too slow, so a copy of the checker with the same comparison and a
# 65536-byte limit checks the boundary. The production copy and the 1 GiB
# fixture above keep the real limit covered.
bound_cap=65536
bound_ok=$((bound_cap - husize))
[ "$bound_ok" -gt 0 ] || fail "the exact-bound fixture needs a limit above the plist size"

# make_bound_ipa OUT SIZE: the stored bundle plist plus one deflate entry that
# expands to SIZE zero bytes. The declared total is husize + SIZE.
make_bound_ipa() {
  local out=$1 size=$2 plain="$work/bound-plain" packed="$work/bound-deflate"
  local bsize bcrc first central
  head -c "$size" /dev/zero > "$plain"
  deflate_file "$plain" "$packed"
  bsize=$(wc -c < "$packed" | tr -d ' ')
  bcrc=$(zip_crc_file "$plain")
  first=$((30 + ${#hname} + husize))
  central=$((first + 30 + ${#other} + bsize + 46 + ${#hname}))
  printf '%s\n' "$hname|$hname|$work/p/good.xml||0|0|1|1||" \
    "$other|$other|$packed||0|8|1|1||" > "$work/spec-bound"
  raw_zip_spec "$out" "$work/spec-bound"
  patch_le32 "$out" $((first + 14)) "$bcrc"
  patch_le32 "$out" $((first + 22)) "$size"
  patch_le32 "$out" $((central + 16)) "$bcrc"
  patch_le32 "$out" $((central + 24)) "$size"
}

sed 's/\$total > 1073741824/\$total > 65536/' "$checker" > "$work/bound-checker.sh"
make_bound_ipa "$work/bound-exact.ipa" "$bound_ok"
status=0
out=$(sh "$work/bound-checker.sh" --expected-version 0.1.0 --ipa "$work/bound-exact.ipa" 2>&1) || status=$?
checks=$((checks + 1))
expect_status 0 "the aggregate bound accepts exactly its limit"
expect_text "CFBundleShortVersionString is 0.1.0" "the exact-bound fixture is otherwise valid"
make_bound_ipa "$work/bound-over.ipa" "$((bound_ok + 1))"
status=0
out=$(sh "$work/bound-checker.sh" --expected-version 0.1.0 --ipa "$work/bound-over.ipa" 2>&1) || status=$?
checks=$((checks + 1))
expect_status 1 "the aggregate bound refuses one byte over its limit"
expect_text "exceeds uncompressed data bound" "the one-byte-over failure is named"

# The checker must work with the macOS BSD awk and with the GNU awk and mawk
# that Linux distributions provide. Run the XML, binary plist, raw ZIP, and
# Mach-O paths under every available implementation.

awk_paths=""
for cand in awk gawk mawk nawk; do
  if command -v "$cand" >/dev/null 2>&1; then
    cand_path=$(command -v "$cand")
    case " $awk_paths " in
      *" $cand_path "*) ;;
      *) awk_paths="$awk_paths $cand_path" ;;
    esac
  fi
done
for cand in $awk_paths; do
  cand_name=$(basename "$cand")
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/hidden-deflate.ipa"
  expect_status 1 "awk $cand_name rejects hidden deflate bytes"
  run_awk "$cand" --expected-version 0.1.0 --mac-binary "$work/bin-bad-command.bin"
  expect_status 1 "awk $cand_name rejects a malformed load command"
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/good-xml.ipa"
  expect_status 0 "awk $cand_name reads an XML plist"
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/good-bin.ipa"
  expect_status 0 "awk $cand_name reads a binary plist"
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/descriptor.ipa"
  expect_status 0 "awk $cand_name reads a data descriptor"
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/mismatch.ipa"
  expect_status 1 "awk $cand_name rejects a header mismatch"
  expect_text "local name differs from the central directory" "awk $cand_name names the header mismatch"
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/localonly.ipa"
  expect_status 1 "awk $cand_name rejects a local-only entry"
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/nulname.ipa"
  expect_status 1 "awk $cand_name rejects a NUL name"
  run_awk "$cand" --expected-version 0.1.0 --ipa "$work/dupname.ipa"
  expect_status 1 "awk $cand_name rejects a duplicate name"
  run_awk "$cand" --expected-version 0.1.0 --mac-binary "$work/bin-with-text.bin"
  expect_status 3 "awk $cand_name leaves a valid binary unverified"
  run_awk "$cand" --expected-version 0.1.0 --mac-binary "$work/bin-x86.bin"
  expect_status 1 "awk $cand_name rejects a wrong-architecture binary"
done
if [ "$(printf '%s\n' $awk_paths | grep -c . || true)" -lt 2 ]; then
  echo "note: only one awk implementation is available; install gawk or mawk to widen the matrix" >&2
fi

# Short successful reads can expose a complete good prefix of a polyglot.
# Exercise the checked stages through a real stored ZIP entry and CRC.
bin_plist "$work/p/poly-old.bin" CFBundleShortVersionString 9.9.9 CFBundleVersion 1
perl -e '
  use strict; use warnings;
  local $/; my ($first, $last, $out) = @ARGV;
  open my $a, "<", $first or die $!; binmode $a; my $prefix = <$a>;
  open my $b, "<", $last or die $!; binmode $b; my $suffix = <$b>;
  my $shift = length $prefix; my $trailer = length($suffix) - 32;
  my $count = unpack("N", substr($suffix, $trailer + 12, 4));
  my $table = unpack("N", substr($suffix, $trailer + 28, 4));
  for my $i (0 .. $count - 1) {
    my $pos = $table + 2 * $i;
    substr($suffix, $pos, 2) = pack("n", unpack("n", substr($suffix, $pos, 2)) + $shift);
  }
  substr($suffix, $trailer + 28, 4) = pack("N", $table + $shift);
  open my $fh, ">", $out or die $!; binmode $fh; print $fh $prefix, $suffix; close $fh or die $!;
' "$work/p/good.bin" "$work/p/poly-old.bin" "$work/p/poly.bin"
make_ipa "$work/poly.ipa" "$work/p/poly.bin"
run --expected-version 0.1.0 --ipa "$work/poly.ipa"
expect_status 1 "complete binary polyglot does not pass"
expect_text "9.9.9, expected 0.1.0" "complete binary polyglot selects the other version"
cat "$work/p/good.xml" "$work/p/old.xml" > "$work/p/poly.xml"
make_ipa "$work/poly-xml.ipa" "$work/p/poly.xml"
run --expected-version 0.1.0 --ipa "$work/poly-xml.ipa"
expect_status 1 "complete concatenated XML is refused"
reject_text "CFBundleShortVersionString is 0.1.0" "complete concatenated XML cannot pass"
mkdir -p "$work/stage-shim"
real_od=$(command -v od); real_tr=$(command -v tr); real_sed=$(command -v sed)
export real_od real_tr real_sed
HS_PREFIX_SIZE=$(wc -c < "$work/p/good.bin"); export HS_PREFIX_SIZE
HS_XML_SIZE=$(wc -c < "$work/p/good.xml"); export HS_XML_SIZE
cat > "$work/stage-shim/od" <<'SHIM'
#!/bin/sh
case "${4-}" in
  */plist.[0-9]*) head -c "$HS_PREFIX_SIZE" "$4" | "$real_od" -An -v -tu1; exit "$HS_SHIM_STATUS" ;;
esac
exec "$real_od" "$@"
SHIM
cat > "$work/stage-shim/tr" <<'SHIM'
#!/bin/sh
if [ "${1-}" = '\n\r\t' ]; then
  head -c "$HS_XML_SIZE" | "$real_tr" "$@"
  exit "$HS_SHIM_STATUS"
fi
exec "$real_tr" "$@"
SHIM
cat > "$work/stage-shim/sed" <<'SHIM'
#!/bin/sh
case "${2-}" in
  # Emit the whole first plist in the normal split format. A parser that only
  # sees these bytes would accept a matching version from the valid prefix.
  */plist.tr) head -c "$HS_XML_SIZE" "$2" | "$real_sed" "$1"; exit "$HS_SHIM_STATUS" ;;
esac
exec "$real_sed" "$@"
SHIM
chmod +x "$work/stage-shim/od" "$work/stage-shim/tr" "$work/stage-shim/sed"
for stage in od tr sed; do
  for shim_status in 0 1; do
    mkdir -p "$work/one-shim"
    cp "$work/stage-shim/$stage" "$work/one-shim/$stage"
    export HS_SHIM_STATUS=$shim_status
    if [ "$stage" = od ]; then fixture="$work/poly.ipa"; else fixture="$work/poly-xml.ipa"; fi
    status=0
    out=$(PATH="$work/one-shim:$PATH" sh "$checker" --expected-version 0.1.0 --ipa "$fixture" 2>&1) || status=$?
    checks=$((checks + 1))
    expect_status 1 "$stage short output with status $shim_status fails"
    case "$stage:$shim_status" in
      od:0) reason="incomplete plist byte read" ;;
      od:1) reason="cannot read plist bytes" ;;
      tr:0) reason="incomplete plist text read" ;;
      tr:1) reason="cannot normalize plist text" ;;
      sed:0) reason="incomplete plist text split" ;;
      sed:1) reason="cannot split plist text" ;;
    esac
    expect_text "$reason" "$stage shim was exercised"
    reject_text "CFBundleShortVersionString is 0.1.0" "$stage cannot pass a good prefix"
    rm "$work/one-shim/$stage"
  done
done

# Directly test the reader boundary, independent of the archive size gate.
awk '/^plist_read\(\) \{/ { copy=1 } copy { print } copy && /^# Mach-O reader/ { exit }' "$checker" > "$work/reader.sh"
reader_case() {
  status=0
  out=$(work="$work"; max_plist_bytes=262144; awk_bin=awk; . "$work/reader.sh"; plist_read "$1" CFBundleShortVersionString) || status=$?
  checks=$((checks + 1))
  expect_text "$2" "$3"
}
ln -s "$work/p/good.xml" "$work/p/link.xml"
reader_case "$work/p/link.xml" 'ERR the plist is not a regular' 'reader rejects symlinks'
reader_case "$work/p" 'ERR the plist is not a regular' 'reader rejects directories'
reader_case "$work/p/huge.xml" 'ERR the plist is too large' 'reader enforces its own size bound'

# Apple plutil rejects binary UTF-8 objects even when the version matches.
bin_plist "$work/p/b-8-match.bin" CFBundleShortVersionString 8:0.1.0
make_ipa "$work/b-8-match.ipa" "$work/p/b-8-match.bin"
run --expected-version 0.1.0 --ipa "$work/b-8-match.ipa"
expect_status 1 'matching binary UTF-8 value is refused'
expect_text 'UTF-8 binary string is unsupported' 'binary UTF-8 rejection is named'
bin_plist "$work/p/b-8-unused.bin" CFBundleShortVersionString 0.1.0 Unrelated 8:abc
make_ipa "$work/b-8-unused.ipa" "$work/p/b-8-unused.bin"
run --expected-version 0.1.0 --ipa "$work/b-8-unused.ipa"
expect_status 1 'unrelated binary UTF-8 object is refused'
if [ "$(uname -s)" = Darwin ] && command -v plutil >/dev/null 2>&1; then
  if plutil -lint "$work/p/b-8-match.bin" >/dev/null 2>&1; then fail 'Apple plutil accepted binary UTF-8 value'; fi
  if plutil -lint "$work/p/b-8-unused.bin" >/dev/null 2>&1; then fail 'Apple plutil accepted unrelated binary UTF-8 object'; fi
fi

if [ "$failures" -ne 0 ]; then
  echo "artifact_versions_test: $failures of $checks checks failed" >&2
  exit 1
fi
echo "artifact_versions_test: all $checks checks passed"
