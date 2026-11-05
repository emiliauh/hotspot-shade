#!/usr/bin/env bash
# Static checks for the isolated windows/ prototype. This is a convenience
# check on macOS or Linux. The C# test runner holds the authoritative contract
# checks. This script does not build the UWP app and does not run Windows.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
app="$root/src/HotspotShade.WinUI2"
project="$app/HotspotShade.WinUI2.csproj"
manifest="$app/Package.appxmanifest"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

ok() {
    echo "ok: $1"
}

command -v xmllint >/dev/null 2>&1 || fail "xmllint is required"

xml_count=0
while IFS= read -r file; do
    xmllint --noout "$file" || fail "invalid XML: $file"
    xml_count=$((xml_count + 1))
done < <(find "$root" -type f \( -name '*.xaml' -o -name '*.csproj' -o -name '*.appxmanifest' -o -name '*.xml' -o -name '*.config' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*' | sort)
[ "$xml_count" -ge 8 ] || fail "expected at least 8 XML files"
ok "$xml_count XML files are well formed"

if grep -q '<Capability' "$manifest"; then
    fail "the package declares a capability"
fi
if grep -q '<Extensions' "$manifest"; then
    fail "the package declares an extension"
fi
if grep -q 'internetClient\|privateNetworkClientServer\|runFullTrust' "$manifest"; then
    fail "the package mentions a network or full trust capability"
fi
ok "the package has no capability and no extension"

if grep -q 'PackageCertificateKeyFile\|AppxPackageSigningEnabled>true' "$project"; then
    fail "the project contains signing configuration"
fi
if find "$root" -type f \( -name '*.pfx' -o -name '*.cer' -o -name '*.key' -o -name '*.pem' -o -name '*.mobileprovision' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*' | grep -q .; then
    fail "signing material is present"
fi
ok "no signing material is present"

forbidden='System\.Net|HttpClient|TcpClient|TcpListener|UdpClient|WebSocket|Socket|Windows\.Networking|Wintun|FullTrustProcessLauncher|Process\.Start|netsh|route\.exe'
if grep -R -n -E "$forbidden" --include='*.cs' --exclude-dir=bin --exclude-dir=obj --exclude-dir=.vs --exclude-dir=AppPackages --exclude-dir=TestResults "$root/src" "$root/tests" | grep -v 'ContractTests.cs' | grep -q .; then
    fail "forbidden network, process, or tunnel API found"
fi
ok "no forbidden API is present"

for word in 'All data is simulated' 'No tunnel' 'network listener' 'not production ready' 'Simulated'; do
    if ! grep -R -q -F "$word" --include='*.cs' --include='*.xaml' --exclude-dir=bin --exclude-dir=obj --exclude-dir=.vs --exclude-dir=AppPackages --exclude-dir=TestResults "$root/src"; then
        fail "missing simulated label: $word"
    fi
done
ok "the simulated labels are present"

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

while IFS= read -r file; do
    relative="${file#"$app/"}"
    windows_path="${relative//\//\\}"
    if [[ "$file" == *.cs ]]; then
        if ! grep -F -q "<Compile Include=\"$windows_path\"" "$project"; then
            fail "the project does not compile $relative"
        fi
    else
        if ! grep -F -q "<Page Include=\"$windows_path\"" "$project" \
            && ! grep -F -q "<ApplicationDefinition Include=\"$windows_path\"" "$project"; then
            fail "the project does not include the page $relative"
        fi
    fi
done < <(find "$app" -type f \( -name '*.cs' -o -name '*.xaml' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*' | sort)
ok "the app project includes every source file"

for word in 'UWP' 'WinUI 2' 'not production ready' 'Windows 11 SDK'; do
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
    while IFS= read -r file; do
        if ! perl -CSD -ne 'if (/[\x{2013}\x{2014}\x{2018}\x{2019}\x{201C}\x{201D}]/) { exit 1 }' "$file"; then
            fail "forbidden punctuation in $file"
        fi
    done < <(find "$root" -type f \( -name '*.cs' -o -name '*.xaml' -o -name '*.md' -o -name '*.csproj' -o -name '*.appxmanifest' -o -name '*.xml' -o -name '*.config' \) -not -path '*/bin/*' -not -path '*/obj/*' -not -path '*/.vs/*' -not -path '*/AppPackages/*' -not -path '*/TestResults/*')
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
