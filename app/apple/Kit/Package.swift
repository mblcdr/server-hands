// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ServerHandsKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "ServerHandsKit", targets: ["ServerHandsKit"])],
    targets: [
        .target(name: "ServerHandsKit"),
        .testTarget(
            name: "ServerHandsKitTests",
            dependencies: ["ServerHandsKit"],
            resources: [.copy("Resources/v1.json")]
        ),
    ]
)
