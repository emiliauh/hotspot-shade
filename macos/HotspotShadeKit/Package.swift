// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "HotspotShadeKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "HotspotShadeKit", targets: ["HotspotShadeKit"]),
        .executable(name: "HotspotShadeHelper", targets: ["HotspotShadeHelper"]),
    ],
    targets: [
        .target(name: "HotspotShadeKit"),
        .executableTarget(name: "HotspotShadeHelper", dependencies: ["HotspotShadeKit"]),
        .testTarget(
            name: "HotspotShadeKitTests",
            dependencies: ["HotspotShadeKit"],
            exclude: ["Fixtures"]
        ),
    ]
)
