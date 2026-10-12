// swift-tools-version:5.9
import PackageDescription

// PoC harness: tinfoil-swift 0.8.2's pure-Swift EHBP session layer (the files the
// iOS app ships), built against the pinned EHBP 0.3.2 and openai-swift-fork 0.0.15,
// with the Go verifier binary target removed (not needed to exercise response handling).
let package = Package(
    name: "poc-swift-forged-response",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "TinfoilAI", targets: ["TinfoilAI"])],
    dependencies: [
        .package(path: "../openai-swift-fork"),
        .package(path: "../ehbp-0.3.2"),
    ],
    targets: [
        .target(
            name: "TinfoilAI",
            dependencies: [
                .product(name: "OpenAI", package: "openai-swift-fork"),
                .product(name: "EHBP", package: "ehbp-0.3.2"),
            ],
            path: "Sources/TinfoilAI"),
        .testTarget(
            name: "PoCTests",
            dependencies: ["TinfoilAI", .product(name: "OpenAI", package: "openai-swift-fork"), .product(name: "EHBP", package: "ehbp-0.3.2")],
            path: "Tests/PoCTests"),
    ]
)
