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
        .executable(name: "atlas-passkey", targets: ["atlas-passkey"]),
        .executable(name: "atlas-platform-sso", targets: ["atlas-platform-sso"]),
        .executable(name: "atlas-platform-sso-host", targets: ["atlas-platform-sso-host"]),
    ],
    targets: [
        // scrypt (16 MiB, N=16384) is unusably slow unoptimised, so keep optimisation on even in debug/test builds.
        .target(name: "AtlasDesktopCore", swiftSettings: [.unsafeFlags(["-O"], .when(configuration: .debug))]),
        .executableTarget(name: "atlas-sync", dependencies: ["AtlasDesktopCore"]),
        .executableTarget(name: "atlas-enroll", dependencies: ["AtlasDesktopCore"]),
        .executableTarget(name: "atlas-pam-helper", dependencies: ["AtlasDesktopCore"]),
        .executableTarget(name: "atlas-passkey", dependencies: ["AtlasDesktopCore"]),
        // Platform SSO: an app extension (entry point NSExtensionMain, set at link time) and the app that carries it.
        .executableTarget(
            name: "atlas-platform-sso",
            dependencies: ["AtlasDesktopCore"],
            swiftSettings: [.unsafeFlags(["-application-extension"])],
            linkerSettings: [.unsafeFlags(["-Xlinker", "-e", "-Xlinker", "_NSExtensionMain"])]
        ),
        .executableTarget(name: "atlas-platform-sso-host"),
        .testTarget(
            name: "AtlasDesktopCoreTests",
            dependencies: ["AtlasDesktopCore"],
            resources: [.copy("Resources/protocol-vectors.json")]
        ),
    ]
)
