#!/bin/sh
# Build one unsigned HotspotShade .deb for Linux.
#
# Run on a Debian-family Linux host with Node.js 22 or later, Rust, and dpkg-deb.
# The script uses the committed lockfiles. It downloads no script and does not
# need an elevated command.
#
#   ARCH=x64 linux/scripts/package-deb.sh
#
# The package is for Debian and Ubuntu only. The baseline is Ubuntu 24.04 with
# glibc 2.39: the engine and the helper are built on the host and link against
# its glibc, so build on Ubuntu 24.04. The script stops on a build host that
# is not Debian-family or whose glibc is newer than 2.39 (see
# HOTSPOTSHADE_ALLOW_NEWER_GLIBC). Install needs a polkit authentication agent
# in the desktop session for the pkexec password prompt.
#
# The package holds the Electron app, the Rust engine, the pkexec helper, the
# polkit action, the desktop entry, and the icon. The app runs as the desktop
# user. The helper runs one fixed engine path and takes no arguments. The
# maintainer scripts are in linux/packaging/debian: postinst creates the state
# directory, prerm refuses a remove or upgrade while the helper or an engine may
# still be running, and postrm removes the state directory on purge only.

set -eu

# The root helper refuses engine paths with group- or world-writable parents.
# Do not let the invoking shell's umask make the package unusable.
umask 022

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
repo=$(CDPATH= cd -- "$root/.." && pwd)
arch=${ARCH:-x64}
case "$arch" in
  x64) debarch=amd64 ;;
  arm64) debarch=arm64 ;;
  *)
    echo "Use ARCH=x64 or ARCH=arm64." >&2
    exit 2
    ;;
esac

version=$(node -p "require('$root/package.json').version")
host=$(uname -m)
case "$arch:$host" in
  x64:x86_64) ;;
  arm64:aarch64|arm64:arm64) ;;
  *)
    echo "Build the $arch package on a $arch host. This host is $host." >&2
    exit 2
    ;;
esac

# shellcheck source=package-deb-lib.sh
. "$root/scripts/package-deb-lib.sh"
glibc_text=$(getconf GNU_LIBC_VERSION 2> /dev/null || true)
hs_check_build_host /etc/os-release "$glibc_text" "${HOTSPOTSHADE_ALLOW_NEWER_GLIBC:-0}" || exit 2

build="$root/build/deb-$debarch"
out="$root/build/hotspotshade_${version}_${debarch}.deb"

if [ ! -x "$root/node_modules/.bin/electron-packager" ] && [ ! -x "$root/node_modules/.bin/electron-packager.cjs" ]; then
  echo "Run npm ci in linux first." >&2
  exit 2
fi

rm -rf "$build"
mkdir -p "$build"

echo "Building the Rust engine."
cargo build --release --locked --manifest-path "$repo/rust/Cargo.toml"

echo "Building the pkexec helper."
cargo build --release --locked --manifest-path "$root/helper/Cargo.toml"

echo "Building the Electron app."
(
  cd "$root"
  ./node_modules/.bin/electron-packager . HotspotShade \
    --platform=linux \
    --arch="$arch" \
    --out="$build/app" \
    --overwrite \
    --asar \
    --prune=true \
    --app-copyright="HotspotShade" \
    --executable-name=HotspotShade \
    --ignore='^/node_modules' \
    --ignore='^/build' \
    --ignore='^/test' \
    --ignore='^/scripts' \
    --ignore='^/helper' \
    --ignore='^/packaging' \
    --ignore='^/\.shots'
)

appdir=$(find "$build/app" -maxdepth 1 -mindepth 1 -type d | head -n 1)
if [ -z "$appdir" ]; then
  echo "The Electron app directory is missing." >&2
  exit 1
fi

echo "Building the package tree."
mkdir -p "$build/deb/DEBIAN"
mkdir -p "$build/deb/opt/hotspotshade"
mkdir -p "$build/deb/opt/hotspotshade/resources/engine"
mkdir -p "$build/deb/usr/bin"
mkdir -p "$build/deb/usr/lib/hotspotshade"
mkdir -p "$build/deb/usr/share/applications"
mkdir -p "$build/deb/usr/share/pixmaps"
mkdir -p "$build/deb/usr/share/polkit-1/actions"

cp -R "$appdir/." "$build/deb/opt/hotspotshade/"
cp "$repo/rust/target/release/hotspotshade" "$build/deb/opt/hotspotshade/resources/engine/hotspotshade"
cp "$root/helper/target/release/hotspotshade-helper" "$build/deb/usr/lib/hotspotshade/hotspotshade-helper"
cp "$root/packaging/hotspotshade.desktop" "$build/deb/usr/share/applications/hotspotshade.desktop"
cp "$root/assets/icon.png" "$build/deb/usr/share/pixmaps/hotspotshade.png"
cp "$root/packaging/local.hotspotshade.tunnel.policy" "$build/deb/usr/share/polkit-1/actions/local.hotspotshade.tunnel.policy"

cat > "$build/deb/usr/bin/hotspotshade" <<'WRAPPER'
#!/bin/sh
exec /opt/hotspotshade/HotspotShade "$@"
WRAPPER
chmod 0755 "$build/deb/usr/bin/hotspotshade"

chmod 0755 "$build/deb/opt/hotspotshade/HotspotShade"
chmod 0755 "$build/deb/opt/hotspotshade/resources/engine/hotspotshade"
chmod 0755 "$build/deb/usr/lib/hotspotshade/hotspotshade-helper"
chmod 0644 "$build/deb/usr/share/applications/hotspotshade.desktop"
chmod 0644 "$build/deb/usr/share/pixmaps/hotspotshade.png"
chmod 0644 "$build/deb/usr/share/polkit-1/actions/local.hotspotshade.tunnel.policy"

if [ -f "$build/deb/opt/hotspotshade/chrome-sandbox" ]; then
  chmod 4755 "$build/deb/opt/hotspotshade/chrome-sandbox"
fi

# Derive the shared-library Depends from the built binaries when dpkg-shlibdeps
# exists. It needs a debian/control file in its working directory.
derived=""
if command -v dpkg-shlibdeps > /dev/null 2>&1; then
  shlibs="$build/shlibdeps"
  mkdir -p "$shlibs/debian"
  printf 'Source: hotspotshade\n\nPackage: hotspotshade\nArchitecture: any\n' > "$shlibs/debian/control"
  if derived_output=$(
    cd "$shlibs" && dpkg-shlibdeps -O --ignore-missing-info \
      -l"$build/deb/opt/hotspotshade" \
      -e"$build/deb/opt/hotspotshade/HotspotShade" \
      -e"$build/deb/opt/hotspotshade/resources/engine/hotspotshade" \
      -e"$build/deb/usr/lib/hotspotshade/hotspotshade-helper"
  ); then
    derived=$(printf '%s\n' "$derived_output" | sed -n 's/^shlibs:Depends=//p')
  else
    echo "WARNING: dpkg-shlibdeps failed; Depends lists only the known libraries and libc6." >&2
  fi
else
  echo "WARNING: dpkg-shlibdeps is not installed; Depends lists only the known libraries and libc6." >&2
  echo "WARNING: install dpkg-dev on the build host for a derived Depends." >&2
fi
if [ -z "$derived" ]; then
  # Without a derived list, pin libc6 to the glibc this host built against. The
  # real minimum may be lower; the package never claims a glibc it was not built
  # with.
  glibc_version=${glibc_text#glibc }
  derived="libc6 (>= $glibc_version)"
fi
depends=$(hs_merge_depends "$derived")

cat > "$build/deb/DEBIAN/control" <<CONTROL
Package: hotspotshade
Version: $version
Section: net
Priority: optional
Architecture: $debarch
Maintainer: HotspotShade
Depends: $depends
Recommends: $HS_RECOMMENDS
Description: HotspotShade target app for Linux
 HotspotShade re-originates tethered IPv4 flows with TTL 65 and pins every
 outer socket to the physical hotspot interface. The package holds the
 Electron app, the Rust engine, and the pkexec helper.
 .
 Debian and Ubuntu only; built for Ubuntu 24.04 (glibc 2.39). Starting the
 tunnel runs a root helper through pkexec, so the desktop session needs a
 polkit authentication agent to show the password prompt. Removing or
 upgrading the package is refused while the helper or an engine may still be
 running; purging it deletes /var/lib/hotspotshade, which holds the engine
 identity key and the pairing trust list.
CONTROL

# Maintainer scripts. They are plain files so the packaging test can run them.
install -m 0755 "$root/packaging/debian/postinst" "$build/deb/DEBIAN/postinst"
install -m 0755 "$root/packaging/debian/prerm" "$build/deb/DEBIAN/prerm"
install -m 0755 "$root/packaging/debian/postrm" "$build/deb/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$build/deb" "$out"
echo "Wrote $out"
