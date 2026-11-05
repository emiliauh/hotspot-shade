// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "HotspotShadeKit", platforms: [.macOS(.v14)], products: [.library(name: "HotspotShadeKit", targets: ["HotspotShadeKit"])], targets: [.target(name: "HotspotShadeKit"), .testTarget(name: "HotspotShadeKitTests", dependencies: ["HotspotShadeKit"])])
