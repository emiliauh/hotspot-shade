#!/bin/sh
# Static checks for the windows/ tree. This is a convenience check on macOS
# or Linux. The C# test runner holds the authoritative contract checks. This
# script does not build the UWP app and does not run Windows. It is POSIX sh,
# so both `sh` and `bash` run it.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
app="$root/src/HotspotShade.WinUI2"
project="$app/HotspotShade.WinUI2.csproj"
manifest="$app/Package.appxmanifest"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/check-static-contract.XXXXXX")"
trap 'rm -rf "$tmpdir"' 0 1 2 15

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

ok() {
    echo "ok: $1"
}

command -v xmllint >/dev/null 2>&1 || fail "xmllint is required"

xml_count=0
find "$root" -type f \( -name '*.xaml' -o -name '*.csproj' -o -name '*.appxmanifest' -o -name '*.xml' -o -name '*.config' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*' | sort > "$tmpdir/xml_files"
while IFS= read -r file; do
    xmllint --noout "$file" || fail "invalid XML: $file"
    xml_count=$((xml_count + 1))
done < "$tmpdir/xml_files"
[ "$xml_count" -ge 8 ] || fail "expected at least 8 XML files"
ok "$xml_count XML files are well formed"

capabilities="$(grep -o '<rescap:Capability Name="[A-Za-z]*"' "$manifest" | sed 's/.*Name="//; s/"$//' | sort | tr '\n' ' ')"
[ "$capabilities" = "allowElevation runFullTrust " ] || fail "the package must declare exactly runFullTrust and allowElevation (found: $capabilities)"
if grep -q 'internetClient\|privateNetworkClientServer\|<DeviceCapability' "$manifest"; then
    fail "the package declares a network or device capability"
fi
grep -q 'Category="windows.fullTrustProcess"' "$manifest" || fail "the package does not declare the broker"
grep -q 'Executable="Broker\\HotspotShade.WinUI2.Broker.exe"' "$manifest" || fail "the broker path is not fixed"
grep -q 'EntryPoint="Windows.FullTrustApplication"' "$manifest" || fail "the broker extension lacks EntryPoint Windows.FullTrustApplication"
grep -q '<uap:AppService Name="hotspotshade.engine" />' "$manifest" || fail "the app service is not declared"
ok "the package declares the broker, the app service, runFullTrust, and allowElevation only"

if grep -q 'PackageCertificateKeyFile\|AppxPackageSigningEnabled>true' "$project"; then
    fail "the project contains signing configuration"
fi
if find "$root" -type f \( -name '*.pfx' -o -name '*.cer' -o -name '*.key' -o -name '*.pem' -o -name '*.mobileprovision' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*' | grep -q .; then
    fail "signing material is present"
fi
ok "no signing material is present"

src_files() {
    find "$root/src" -type f -name '*.cs' -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*'
}

forbidden='System\.Net|HttpClient|TcpClient|TcpListener|UdpClient|WebSocket|Windows\.Networking|netsh|route\.exe|TerminateProcess|SetEnvironmentVariable'
if src_files | xargs grep -n -E "$forbidden" | grep -q .; then
    src_files | xargs grep -n -E "$forbidden" >&2
    fail "forbidden network, shell, or termination API found"
fi
if src_files | grep -v '/HotspotShade.WinUI2.ReleaseProbe/' | xargs grep -n 'Process\.Start' | grep -q .; then
    fail "Process.Start outside the read-only release probe"
fi
if src_files | grep -v '/HotspotShade.WinUI2.Broker/ElevatedEngineLauncher.cs$' | xargs grep -n '"runas"' | grep -q .; then
    fail "the runas verb appears outside ElevatedEngineLauncher.cs"
fi
if src_files | grep -v '/HotspotShade.WinUI2/Services/BrokerConnection.cs$' | xargs grep -n 'FullTrustProcessLauncher' | grep -q .; then
    fail "FullTrustProcessLauncher appears outside BrokerConnection.cs"
fi
if grep -R -n -E 'CreateProcess|CreatePipe|WinHttp|DllImport|ShellExecute|127\.0\.0\.1' --include='*.cs' --exclude-dir=bin --exclude-dir=obj "$app" "$root/src/HotspotShade.WinUI2.Core/App" | grep -q .; then
    fail "the window or the core holds a process, pipe, or loopback client API"
fi
ok "no forbidden API is present and elevation stays in one file"

if grep -R -n -i -E 'simulat|demo|preview' --include='*.cs' --include='*.xaml' --include='*.appxmanifest' --exclude-dir=bin --exclude-dir=obj "$app" | grep -q .; then
    grep -R -n -i -E 'simulat|demo|preview' --include='*.cs' --include='*.xaml' --include='*.appxmanifest' --exclude-dir=bin --exclude-dir=obj "$app" >&2
    fail "the app has a demo, preview, or simulated surface"
fi
if find "$root/src/HotspotShade.WinUI2.Core" -name 'Demo*.cs' -not -path '*/bin/*' -not -path '*/obj/*' | grep -q .; then
    fail "a simulated session source is present"
fi
ok "the app has no demo, preview, or simulated surface"

if ! grep -q '<Version>2.8.7</Version>' "$project"; then
    fail "WinUI 2.8.7 is not pinned"
fi
if ! grep -q '<Version>6.2.15</Version>' "$project"; then
    fail "the UWP package is not pinned"
fi
if grep -q '<Version>[^<]*\(\*\|\[\|(\)' "$project"; then
    fail "a floating or range package version is present"
fi
ok "the dependency versions are pinned"

for asset in Square44x44Logo.png Square150x150Logo.png SplashScreen.png StoreLogo.png; do
    [ -s "$app/Assets/$asset" ] || fail "missing asset: $asset"
done
ok "the manifest assets are present"

find "$app" -type f \( -name '*.cs' -o -name '*.xaml' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*' | sort > "$tmpdir/app_sources"
while IFS= read -r file; do
    relative="${file#"$app/"}"
    windows_path="$(printf '%s' "$relative" | tr '/' '\\')"
    case "$file" in
        *.cs)
            if ! grep -F -q "<Compile Include=\"$windows_path\"" "$project"; then
                fail "the project does not compile $relative"
            fi
            ;;
        *)
            if ! grep -F -q "<Page Include=\"$windows_path\"" "$project" \
                && ! grep -F -q "<ApplicationDefinition Include=\"$windows_path\"" "$project"; then
                fail "the project does not include the page $relative"
            fi
            ;;
    esac
done < "$tmpdir/app_sources"
ok "the app project includes every source file"

[ -s "$root/BUILD_AND_TEST_ON_PC.md" ] || fail "BUILD_AND_TEST_ON_PC.md is missing"
for word in 'UWP' 'WinUI 2' 'not production ready' 'Windows 11 SDK' 'BUILD_AND_TEST_ON_PC.md'; do
    if ! grep -q -F "$word" "$root/README.md"; then
        fail "README is missing: $word"
    fi
done
if ! grep -q 'Incomplete' "$root/PARITY.md"; then
    fail "PARITY is missing the incomplete summary"
fi
if ! grep -q 'not production ready' "$root/PARITY.md"; then
    fail "PARITY does not state the readiness limit"
fi
ok "the docs state the architecture and the limits"

if command -v perl >/dev/null 2>&1; then
    find "$root" -type f \( -name '*.cs' -o -name '*.xaml' -o -name '*.md' -o -name '*.csproj' -o -name '*.appxmanifest' -o -name '*.xml' -o -name '*.config' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*' > "$tmpdir/all_files"
    while IFS= read -r file; do
        if ! perl -CSD -ne 'if (/[\x{2013}\x{2014}\x{2018}\x{2019}\x{201C}\x{201D}]/) { exit 1 }' "$file"; then
            fail "forbidden punctuation in $file"
        fi
    done < "$tmpdir/all_files"
    ok "the source and docs use ASCII punctuation"
else
    echo "skip: perl is not available for the punctuation check"
fi

if command -v node >/dev/null 2>&1; then
    node "$root/tools/check_csharp_balance.mjs" "$root" || fail "C# delimiter check failed"
else
    echo "skip: node is not available for the C# delimiter check"
fi

echo "STATIC CONTRACT CHECK PASSED"
