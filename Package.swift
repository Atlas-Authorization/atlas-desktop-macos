// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AtlasDesktop",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "AtlasDesktopCore", targets: ["AtlasDesktopCore"]),
        .executable(name: "atlas-sync", targets: ["atlas-sync"]),
        .executable(name: "atlas-enroll", targets: ["atlas-enroll"]),
        .executable(name: "atlas-pam-helper", targets: ["atlas-pam-helper"]),
    ],
    targets: [
        // scrypt (16 MiB, N=16384) is unusably slow unoptimised, so keep optimisation on even in debug/test builds.
        .target(name: "AtlasDesktopCore", swiftSettings: [.unsafeFlags(["-O"], .when(configuration: .debug))]),
        .executableTarget(name: "atlas-sync", dependencies: ["AtlasDesktopCore"]),
        .executableTarget(name: "atlas-enroll", dependencies: ["AtlasDesktopCore"]),
        .executableTarget(name: "atlas-pam-helper", dependencies: ["AtlasDesktopCore"]),
        .testTarget(
            name: "AtlasDesktopCoreTests",
            dependencies: ["AtlasDesktopCore"],
            resources: [.copy("Resources/protocol-vectors.json")]
        ),
    ]
)
