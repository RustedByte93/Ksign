//
//  LocalInstallerRedactor.swift
//  Ksign
//
//  Removes secrets and identifiers from free text before it enters the diagnostics log or an export.
//  Foundation only, so it is unit-tested in Tests/LocalInstaller.
//

import Foundation

enum Redactor {
	private static let patterns: [NSRegularExpression] = [
		// UDIDs: 00008110-001A2B3C4D5E6F70 and legacy 40-hex
		"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}",
		"\\b[0-9A-Fa-f]{40}\\b",
		// PEM blocks of any kind that contain key material
		"-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----",
		// user home / container paths
		"/Users/[^/\\s]+",
		"/var/mobile/Containers/[^\\s\"']+",
		// anything that looks like a password assignment
		"(?i)(password|passwd|pwd|secret|token)\\s*[=:]\\s*\\S+",
	].compactMap { try? NSRegularExpression(pattern: $0) }

	static func clean(_ text: String, limit: Int = 600) -> String {
		var s = text
		for p in patterns {
			s = p.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: "<redacted>")
		}
		return s.count > limit ? String(s.prefix(limit)) + "…" : s
	}
}
