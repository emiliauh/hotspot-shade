// swift-tools-version: 5.9
import PackageDescription

// Build-only installer foundation. This package never installs anything. It
// checks signed artifacts that a release builder supplies, stages a payload in
// a private output directory, and builds one unsigned component package.
let package = Package(
    name: "HotspotShadeInstaller",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "HotspotShadeInstallerCore", targets: ["HotspotShadeInstallerCore"]),
        .executable(name: "hotspotshade-installer-build", targets: ["hotspotshade-installer-build"]),
        .executable(
            name: "hotspotshade-installer-coordinator",
            targets: ["hotspotshade-installer-coordinator"]
        ),
    ],
    dependencies: [
        // The helper trust rules live in HotspotShadeKit. The installer reuses
        // them instead of copying them, so the two cannot drift apart.
        .package(path: "../HotspotShadeKit"),
    ],
    targets: [
        .target(
            name: "HotspotShadeInstallerCore",
            dependencies: [.product(name: "HotspotShadeKit", package: "HotspotShadeKit")]
        ),
        .executableTarget(
            name: "hotspotshade-installer-build",
            dependencies: ["HotspotShadeInstallerCore"]
        ),
        .executableTarget(
            name: "hotspotshade-installer-coordinator",
            dependencies: ["HotspotShadeInstallerCore"]
        ),
        .testTarget(
            name: "HotspotShadeInstallerCoreTests",
            dependencies: ["HotspotShadeInstallerCore"]
        ),
    ]
)
