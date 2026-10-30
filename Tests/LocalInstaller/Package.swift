// swift-tools-version:5.9
import PackageDescription

let package = Package(
	name: "LocalInstaller",
	platforms: [.macOS(.v13)],
	dependencies: [
		.package(url: "https://github.com/vapor/vapor.git", from: "4.104.0"),
		.package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.0.0"),
	],
	targets: [
		.target(
			name: "LocalInstallerCore",
			dependencies: [
				.product(name: "Vapor", package: "vapor"),
				.product(name: "NIOSSL", package: "swift-nio-ssl"),
			]
		),
		.testTarget(
			name: "LocalInstallerTests",
			dependencies: [
				"LocalInstallerCore",
				.product(name: "Vapor", package: "vapor"),
				.product(name: "XCTVapor", package: "vapor"),
			]
		),
	]
)
