# Functions for package-deb.sh. Source this file; it runs nothing by itself.
#
# Keeping the build-host check and the Depends merge here lets the packaging
# test run them against fixture inputs with no Linux host and no dpkg tools.

# The package is built and tested on Ubuntu 24.04 (glibc 2.39). A binary links
# against the build host's glibc, and a package built against a newer glibc will
# not run on 24.04. Older build hosts are fine: glibc keeps old symbol versions.
HS_BASELINE_PRETTY="Ubuntu 24.04"
HS_BASELINE_GLIBC_MAJOR=2
HS_BASELINE_GLIBC_MINOR=39

# Runtime libraries the Electron app needs, from scripts/Dockerfile.test. Ubuntu
# 24.04 renamed several packages with a t64 suffix, so each lists both names.
# dpkg-shlibdeps adds the versioned entries (libc6 and the rest) when it runs.
HS_KNOWN_DEPENDS="libasound2t64 | libasound2, libatk-bridge2.0-0t64 | libatk-bridge2.0-0, libatk1.0-0t64 | libatk1.0-0, libcairo2, libcups2t64 | libcups2, libdrm2, libgbm1, libgl1, libgtk-3-0t64 | libgtk-3-0, libnss3, libpango-1.0-0, libx11-xcb1, libxkbcommon0, libxshmfence1, libxss1, xdg-utils, pkexec"
HS_KNOWN_DEPENDS_NAMES="libasound2t64 libasound2 libatk-bridge2.0-0t64 libatk-bridge2.0-0 libatk1.0-0t64 libatk1.0-0 libcairo2 libcups2t64 libcups2 libdrm2 libgbm1 libgl1 libgtk-3-0t64 libgtk-3-0 libnss3 libpango-1.0-0 libx11-xcb1 libxkbcommon0 libxshmfence1 libxss1 xdg-utils pkexec"

# pkexec needs a polkit authentication agent running in the desktop session to
# show the password prompt. GNOME and KDE provide one; many tiling setups do not.
# It is a Recommends because a desktop may supply its own. The names are
# unverified on a real host.
HS_RECOMMENDS="policykit-1-gnome | polkit-kde-agent-1 | lxqt-policykit | mate-polkit"

hs_version_part() {
  # $1 is text such as "glibc 2.39"; $2 is the field: 1 major, 2 minor.
  printf '%s\n' "$1" | sed 's/[^0-9.]//g' | awk -F. -v field="$2" '{ print $field + 0 }'
}

# Returns 0 when "$1" names a glibc version newer than the baseline.
hs_glibc_newer_than_baseline() {
  major=$(hs_version_part "$1" 1)
  minor=$(hs_version_part "$1" 2)
  if [ "$major" -gt "$HS_BASELINE_GLIBC_MAJOR" ]; then
    return 0
  fi
  if [ "$major" -eq "$HS_BASELINE_GLIBC_MAJOR" ] && [ "$minor" -gt "$HS_BASELINE_GLIBC_MINOR" ]; then
    return 0
  fi
  return 1
}

hs_os_release_value() {
  # $1 file, $2 key. Prints the value without quotes.
  sed -n "s/^$2=//p" "$1" 2> /dev/null | head -n 1 | tr -d "\"'"
}

# Check the build host. $1 is an os-release file, $2 the getconf glibc text
# ("glibc 2.39"), $3 is 1 to allow a newer glibc with a warning. Returns 0 when
# the build may go on and 2 when it must stop. Messages go to stderr.
hs_check_build_host() {
  osrelease=$1
  glibc_text=$2
  allow_newer=${3:-0}
  if [ ! -r "$osrelease" ]; then
    echo "Cannot read $osrelease. This package is for Debian and Ubuntu only; build it on $HS_BASELINE_PRETTY." >&2
    return 2
  fi
  id=$(hs_os_release_value "$osrelease" ID)
  id_like=$(hs_os_release_value "$osrelease" ID_LIKE)
  version_id=$(hs_os_release_value "$osrelease" VERSION_ID)
  family=0
  for word in $id $id_like; do
    case "$word" in
      debian | ubuntu) family=1 ;;
    esac
  done
  if [ "$family" -ne 1 ]; then
    echo "This build host is '${id:-unknown}'. The package is for Debian and Ubuntu only (apt, dpkg, polkit, glibc). Build it on $HS_BASELINE_PRETTY." >&2
    return 2
  fi
  case "$glibc_text" in
    glibc\ [0-9]*) ;;
    *)
      echo "Cannot read a glibc version from '${glibc_text}'. The package needs a glibc build host: $HS_BASELINE_PRETTY (glibc ${HS_BASELINE_GLIBC_MAJOR}.${HS_BASELINE_GLIBC_MINOR})." >&2
      return 2
      ;;
  esac
  if hs_glibc_newer_than_baseline "$glibc_text"; then
    if [ "$allow_newer" = "1" ]; then
      {
        echo "WARNING: this build host has $glibc_text, newer than the ${HS_BASELINE_PRETTY} baseline (glibc ${HS_BASELINE_GLIBC_MAJOR}.${HS_BASELINE_GLIBC_MINOR})."
        echo "WARNING: the engine and the helper will need that newer glibc and will not run on $HS_BASELINE_PRETTY."
        echo "WARNING: continuing only because HOTSPOTSHADE_ALLOW_NEWER_GLIBC=1 is set."
      } >&2
      return 0
    fi
    {
      echo "This build host has $glibc_text, newer than the ${HS_BASELINE_PRETTY} baseline (glibc ${HS_BASELINE_GLIBC_MAJOR}.${HS_BASELINE_GLIBC_MINOR})."
      echo "A package built here would not run on $HS_BASELINE_PRETTY. Build on $HS_BASELINE_PRETTY."
      echo "To build for hosts with this newer glibc only, set HOTSPOTSHADE_ALLOW_NEWER_GLIBC=1."
    } >&2
    return 2
  fi
  if [ "$id" != "ubuntu" ] || [ "$version_id" != "24.04" ]; then
    echo "NOTE: the tested build baseline is $HS_BASELINE_PRETTY; this host is ${id}${version_id:+ }${version_id}. The package is untested from this host." >&2
  fi
  return 0
}

# Merge the dpkg-shlibdeps list ("$1", may be empty) into the known list. Where
# the known list names a package that the derived list also names, the derived
# entry replaces the bare name, so its version constraint is kept: a known group
# "libgtk-3-0t64 | libgtk-3-0" and a derived "libgtk-3-0t64 (>= 3.24.0)" give
# "libgtk-3-0t64 (>= 3.24.0) | libgtk-3-0". Derived entries that are not in the
# known list come first. Prints the Depends value.
hs_merge_depends() {
  awk -v derived="$1" -v known="$HS_KNOWN_DEPENDS" '
    function trim(text) { gsub(/^ +| +$/, "", text); return text }
    function pkgname(text,    name) { name = text; sub(/ .*/, "", name); sub(/\(.*/, "", name); return name }
    BEGIN {
      count = split(derived, parts, ",")
      for (i = 1; i <= count; i++) {
        item = trim(parts[i])
        if (item == "") continue
        if (index(item, "|") > 0) { complex[++complex_count] = item; continue }
        name = pkgname(item)
        if (!(name in simple)) order[++order_count] = name
        simple[name] = item
      }
      groups = split(known, group_parts, ",")
      for (g = 1; g <= groups; g++) {
        group = trim(group_parts[g])
        if (group == "") continue
        alternatives = split(group, alt_parts, "|")
        text = ""
        for (a = 1; a <= alternatives; a++) {
          alt = trim(alt_parts[a])
          name = pkgname(alt)
          if (name in simple) { alt = simple[name]; used[name] = 1 }
          text = (text == "" ? alt : text " | " alt)
        }
        merged[++merged_count] = text
      }
      out = ""
      for (i = 1; i <= order_count; i++) {
        if (!(order[i] in used)) out = (out == "" ? simple[order[i]] : out ", " simple[order[i]])
      }
      for (i = 1; i <= complex_count; i++) out = (out == "" ? complex[i] : out ", " complex[i])
      for (i = 1; i <= merged_count; i++) out = (out == "" ? merged[i] : out ", " merged[i])
      print out
    }
  ' < /dev/null
}
