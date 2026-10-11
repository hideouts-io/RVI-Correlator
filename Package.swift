// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RVICorrelator",
    platforms: [.macOS(.v14)],
    products: [.library(name: "CorrelatorCore", targets: ["CorrelatorCore"]), .executable(name: "RVICorrelator", targets: ["CorrelatorApp"]), .executable(name: "RVICaptureHelper", targets: ["CaptureHelper"]), .executable(name: "RVICaptureWorker", targets: ["CaptureWorker"])],
    targets: [
        .target(name: "CapturePlatform"),
        .target(name: "CorrelatorCore", dependencies: ["CapturePlatform"]),
        .executableTarget(name: "CorrelatorApp", dependencies: ["CorrelatorCore"], resources: [.copy("Samples"), .copy("BrandLogo.png")]),
        .executableTarget(name: "CaptureHelper", dependencies: ["CorrelatorCore"]),
        .executableTarget(name: "CaptureWorker", dependencies: ["CorrelatorCore"]),
        .testTarget(name: "CorrelatorCoreTests", dependencies: ["CorrelatorCore"], resources: [.copy("Fixtures")])
    ]
)
