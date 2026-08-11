// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "UniFiPolicyManagerMac",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "UniFiPolicyManagerMac", targets: ["UniFiPolicyManagerMac"])
    ],
    targets: [
        .executableTarget(
            name: "UniFiPolicyManagerMac",
            path: "Sources"
        )
    ]
)
