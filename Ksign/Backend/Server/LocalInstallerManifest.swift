//
//  LocalInstallerManifest.swift
//  Ksign
//
//  Builds and validates the itms-services manifest. Pure Foundation so it is shared by the installer,
//  the on-device self-test and the macOS test package.
//

import Foundation

enum LocalInstallerManifest {
	enum BuildError: LocalizedError {
		case missingField(String)
		case serialization(Error)

		var errorDescription: String? {
			switch self {
			case .missingField(let name): return "manifest field '\(name)' is empty"
			case .serialization(let error): return "manifest serialization failed: \(error.localizedDescription)"
			}
		}
	}

	/// All inputs are explicit (no optionals silently turned into ""): an empty bundle identifier makes
	/// iOS refuse the manifest without any visible reason, so it is rejected here instead.
	static func make(bundleIdentifier: String?, bundleVersion: String?, title: String?, packageURL: URL, displayImageURL: URL) throws -> Data {
		guard let bundleIdentifier, !bundleIdentifier.isEmpty else { throw BuildError.missingField("bundle-identifier") }
		let version = (bundleVersion?.isEmpty == false) ? bundleVersion! : "1.0"
		let plist: [String: Any] = [
			"items": [[
				"assets": [
					["kind": "software-package", "url": packageURL.absoluteString],
					["kind": "display-image", "url": displayImageURL.absoluteString],
				],
				"metadata": [
					"bundle-identifier": bundleIdentifier,
					"bundle-version": version,
					"kind": "software",
					"title": (title?.isEmpty == false) ? title! : bundleIdentifier,
				],
			]],
		]
		do {
			return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
		} catch {
			throw BuildError.serialization(error)
		}
	}

	struct Validation {
		var errors: [String] = []
		var packageURL: URL?
		var bundleIdentifier: String?
		var isValid: Bool { errors.isEmpty }
	}

	/// Checks what iOS checks that we can check: schema, https, and that the package URL points at the
	/// host and port the server is actually bound to (never a stale/hardcoded port).
	static func validate(_ data: Data, expectedHost: String, expectedPort: Int) -> Validation {
		var v = Validation()
		guard
			let root = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
			let items = root["items"] as? [[String: Any]], let item = items.first
		else {
			v.errors.append("not a property list with an 'items' array")
			return v
		}
		let assets = item["assets"] as? [[String: Any]] ?? []
		let metadata = item["metadata"] as? [String: Any] ?? [:]

		for key in ["bundle-identifier", "bundle-version", "kind", "title"] {
			if (metadata[key] as? String)?.isEmpty != false { v.errors.append("metadata.\(key) missing or empty") }
		}
		v.bundleIdentifier = metadata["bundle-identifier"] as? String
		if (metadata["kind"] as? String) != "software" { v.errors.append("metadata.kind must be 'software'") }

		guard let package = assets.first(where: { $0["kind"] as? String == "software-package" }),
			  let urlString = package["url"] as? String, let url = URL(string: urlString)
		else {
			v.errors.append("no software-package asset with a valid url")
			return v
		}
		v.packageURL = url
		if url.scheme != "https" { v.errors.append("software-package url must be https (got \(url.scheme ?? "none"))") }
		if url.host?.lowercased() != expectedHost.lowercased() { v.errors.append("software-package host \(url.host ?? "-") != \(expectedHost)") }
		if url.port != expectedPort { v.errors.append("software-package port \(url.port.map(String.init) ?? "-") != bound port \(expectedPort)") }
		if url.host?.contains("*") == true { v.errors.append("software-package host contains a wildcard") }
		if let image = assets.first(where: { $0["kind"] as? String == "display-image" }), let s = image["url"] as? String, let u = URL(string: s) {
			if u.scheme != "https" || u.port != expectedPort { v.errors.append("display-image url must be https on the bound port") }
		}
		return v
	}
}
