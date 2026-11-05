#!/bin/sh
# Build one unsigned HotspotShade .deb for Linux.
#
# Run on a Linux host with Node.js 22 or later, Rust, and dpkg-deb. The script
# uses the committed lockfiles. It downloads no script and does not need an
# elevated command.
#
#   ARCH=x64 linux/scripts/package-deb.sh
#
# The package holds the Electron app, the Rust engine, the pkexec helper, the
# polkit action, the desktop entry, and the icon. The app runs as the desktop
# user. The helper runs one fixed engine path and takes no arguments.

set -eu

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

cat > "$build/deb/DEBIAN/control" <<CONTROL
Package: hotspotshade
Version: $version
Section: net
Priority: optional
Architecture: $debarch
Maintainer: HotspotShade
Depends: libgtk-3-0 | libgtk-3-0t64, libnss3, libgbm1, libxss1, xdg-utils, pkexec
Description: HotspotShade target app for Linux
 HotspotShade re-originates tethered IPv4 flows with TTL 65 and pins every
 outer socket to the physical hotspot interface. The package holds the
 Electron app, the Rust engine, and the pkexec helper.
CONTROL

cat > "$build/deb/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
install -d -o root -g root -m 0700 /var/lib/hotspotshade
chmod 0755 /opt/hotspotshade/HotspotShade
chmod 0755 /opt/hotspotshade/resources/engine/hotspotshade
chmod 0755 /usr/lib/hotspotshade/hotspotshade-helper
if [ -f /opt/hotspotshade/chrome-sandbox ]; then
  chmod 4755 /opt/hotspotshade/chrome-sandbox
fi
exit 0
POSTINST
chmod 0755 "$build/deb/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "$build/deb" "$out"
echo "Wrote $out"
