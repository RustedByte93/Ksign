//
//  LocalTLSIdentity.swift
//  Ksign
//
//  Resolves, inspects and describes the TLS server identity (certificate + private key) used by the
//  local HTTPS installer. Depends only on Foundation/Security/NIOSSL so it also runs in the macOS test package.
//
//  Sources, in priority order:
//   1. Custom   : Documents/App/Server/custom/{server.crt, server.pem[, hostname.txt][, ca.crt]}
//   2. Bundled  : server.crt / server.pem / commonName.txt / KsignLocalCA.crt inside the app bundle, produced at
//                 build time by Scripts/make-local-pki.sh (private, name-constrained CA + short-lived leaf).
//
//  What this type deliberately does NOT do: it does not decide whether iOS trusts the certificate.
//  `Report.structural` evaluates the leaf against an EXPLICIT anchor with the SSL policy. It answers
//  "is this certificate structurally acceptable to Security.framework (validity <= 825 days, SAN, EKU,
//  name constraints...)", NOT "does the device trust it". Only a real TLS connection evaluated with the
//  default system trust (see LocalInstallerSelfTest) answers the latter. Nothing here is fatal except what
//  makes the HTTPS server impossible to build (unparseable certificate, key mismatch, expired).
//

import Foundation
import NIOSSL
import CryptoKit
import Security

struct LocalTLSIdentity {
	enum Source: String {
		case custom = "Custom (user supplied)"
		case bundled = "Bundled (private Ksign local CA)"
	}

	/// SHA-256 of the DER of the public self-signed `*.backloop.dev` certificate published on
	/// https://backloop.dev/public/ . Its private key is public, and it is valid for 10 years, which
	/// Apple's TLS policy rejects (errSecCertificateValidityPeriodTooLong, -67901) when it is evaluated
	/// against an explicit anchor. Recognised only so diagnostics can say so.
	static let publicBackloopFingerprint = "A6:EE:0D:5E:23:D0:2F:CC:F0:66:D6:03:BC:C9:C6:01:7B:B9:BD:62:E6:75:A3:EF:43:1D:D5:61:EB:36:CA:F1"

	/// Apple: TLS server certificates must not be valid for more than 825 days
	/// (https://support.apple.com/en-us/103769). Measured, not assumed: see LOCAL_INSTALLER.md.
	static let appleMaximumValidityDays = 825

	/// A concrete label under the wildcard. A literal "*.backloop.dev" cannot be used as a hostname.
	static let defaultHostname = "ksign.backloop.dev"

	let source: Source
	let certificateURL: URL
	let keyURL: URL
	let hostname: String
	let report: Report

	// MARK: - Report

	struct StructuralResult {
		let passed: Bool
		let domain: String?
		let code: Int?
		let message: String
		let anchorDescription: String
	}

	struct Report {
		var parsed = false
		var fingerprint = "-"
		var subject = "-"
		var issuer = "-"
		var subjectAltNames: [String] = []
		var notBefore: Date?
		var notAfter: Date?
		var validityDays: Int?
		var isExpired = false
		var isNotYetValid = false
		var isSelfSigned = false
		var isSharedPublicKey = false
		var hostnameInSAN = false
		var keyMatches = false
		var structural: StructuralResult?
		/// Blocking problems: the HTTPS server cannot be built with this identity.
		var problems: [String] = []
		/// Non-blocking observations (e.g. validity above Apple's limit).
		var warnings: [String] = []

		/// The server can be configured with this identity. Says nothing about client trust.
		var isUsable: Bool { parsed && problems.isEmpty && keyMatches && !isExpired && !isNotYetValid }
	}

	enum IdentityError: LocalizedError {
		case notFound
		case invalid(source: Source, problems: [String])

		var errorDescription: String? {
			switch self {
			case .notFound:
				return "No TLS certificate is available. Rebuild the app with `make` (Scripts/make-local-pki.sh) or place server.crt and server.pem in Documents/App/Server/custom/."
			case .invalid(let source, let problems):
				return "The \(source.rawValue) TLS certificate cannot be used by the server: " + problems.joined(separator: "; ")
			}
		}
	}

	// MARK: - Locations

	static var customDirectory: URL {
		URL.documentsDirectory
			.appendingPathComponent("App")
			.appendingPathComponent("Server")
			.appendingPathComponent("custom")
	}

	/// Public CA certificate that should anchor the leaf, if one was shipped/supplied.
	static var anchorCertificateOverride: URL?

	static func anchorCertificateURL() -> URL? {
		if let anchorCertificateOverride { return anchorCertificateOverride }
		let custom = customDirectory.appendingPathComponent("ca.crt")
		if FileManager.default.fileExists(atPath: custom.path) { return custom }
		return Bundle.main.url(forResource: "KsignLocalCA", withExtension: "crt")
	}

	/// Public CA profile (.mobileconfig) shipped in the app for the user to install explicitly.
	static func trustProfileURL() -> URL? {
		Bundle.main.url(forResource: "KsignLocalCA", withExtension: "mobileconfig")
	}

	// MARK: - Resolve

	private static func candidateFiles() -> (source: Source, crt: URL, key: URL, hostname: String)? {
		let fm = FileManager.default
		let customCrt = customDirectory.appendingPathComponent("server.crt")
		let customKey = customDirectory.appendingPathComponent("server.pem")
		if fm.fileExists(atPath: customCrt.path), fm.fileExists(atPath: customKey.path) {
			let host = (try? String(contentsOf: customDirectory.appendingPathComponent("hostname.txt"), encoding: .utf8))?
				.trimmingCharacters(in: .whitespacesAndNewlines)
			return (.custom, customCrt, customKey, (host?.isEmpty == false && host?.contains("*") == false) ? host! : defaultHostname)
		}
		guard
			let crt = Bundle.main.url(forResource: "server", withExtension: "crt"),
			let key = Bundle.main.url(forResource: "server", withExtension: "pem")
		else { return nil }
		return (.bundled, crt, key, resolveHostname())
	}

	/// Inspects the identity that would be used. Never throws, never replaces a custom identity with the
	/// bundled one, so the user is never misled about which certificate is in play.
	static func inspectCurrent() -> LocalTLSIdentity? {
		guard let c = candidateFiles() else { return nil }
		return inspect(source: c.source, crt: c.crt, key: c.key, hostname: c.hostname)
	}

	/// Resolves the identity the server will present. Throws only if the server cannot be built with it.
	static func resolve() throws -> LocalTLSIdentity {
		guard let identity = inspectCurrent() else { throw IdentityError.notFound }
		guard identity.report.isUsable else {
			throw IdentityError.invalid(source: identity.source, problems: identity.report.problems)
		}
		return identity
	}

	/// The hostname the installer URLs use. Cheap (tiny file read) because it is evaluated for every URL.
	/// Never returns a wildcard.
	static func resolveHostname() -> String {
		let fm = FileManager.default
		let candidates: [URL?] = [
			fm.fileExists(atPath: customDirectory.appendingPathComponent("server.crt").path)
				? customDirectory.appendingPathComponent("hostname.txt") : nil,
			Bundle.main.url(forResource: "commonName", withExtension: "txt"),
		]
		for url in candidates.compactMap({ $0 }) {
			if
				let host = (try? String(contentsOf: url, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines),
				!host.isEmpty, !host.contains("*")
			{
				return host
			}
		}
		return defaultHostname
	}

	// MARK: - TLS configuration

	func tlsConfiguration() throws -> TLSConfiguration {
		var config = try TLSConfiguration.makeServerConfiguration(
			certificateChain: try NIOSSLCertificate.fromPEMFile(certificateURL.path).map {
				NIOSSLCertificateSource.certificate($0)
			},
			privateKey: .privateKey(try NIOSSLPrivateKey(file: keyURL.path, format: .pem))
		)
		// iOS clients (itunesstored, Safari) speak TLS 1.2+.
		config.minimumTLSVersion = .tlsv12
		return config
	}

	// MARK: - Inspection

	static func inspect(source: Source, crt: URL, key: URL, hostname: String, now: Date = Date()) -> LocalTLSIdentity {
		var report = Report()
		func result() -> LocalTLSIdentity {
			LocalTLSIdentity(source: source, certificateURL: crt, keyURL: key, hostname: hostname, report: report)
		}

		// Stage 1: parse
		guard
			let pem = try? String(contentsOf: crt, encoding: .utf8),
			let der = firstCertificateDER(fromPEM: pem),
			let info = DERCertificate.parse(der)
		else {
			report.problems.append("certificate file is not a parseable PEM X.509 certificate")
			return result()
		}
		report.parsed = true
		report.fingerprint = fingerprint(of: der)
		report.subject = info.subject
		report.issuer = info.issuer
		report.subjectAltNames = info.dnsNames
		report.notBefore = info.notBefore
		report.notAfter = info.notAfter
		report.isSelfSigned = info.isSelfSigned
		report.isSharedPublicKey = (report.fingerprint == publicBackloopFingerprint)
		report.hostnameInSAN = info.dnsNames.contains { matches(pattern: $0, hostname: hostname) }
		report.validityDays = Int((info.notAfter.timeIntervalSince(info.notBefore) / 86_400).rounded())

		if now > info.notAfter {
			report.isExpired = true
			report.problems.append("certificate expired on \(info.notAfter.formatted(date: .abbreviated, time: .omitted))")
		} else if now < info.notBefore {
			report.isNotYetValid = true
			report.problems.append("certificate is not valid yet (device clock wrong?)")
		}
		if !report.hostnameInSAN {
			report.warnings.append("SAN \(info.dnsNames.isEmpty ? "(none)" : info.dnsNames.joined(separator: ", ")) does not cover \(hostname)")
		}
		if let days = report.validityDays, days > appleMaximumValidityDays {
			report.warnings.append("validity is \(days) days; Apple's TLS policy rejects server certificates valid for more than \(appleMaximumValidityDays) days unless trust comes from a user/administrator-installed root")
		}
		if report.isSharedPublicKey {
			report.warnings.append("this is the publicly published backloop.dev certificate: its private key is public, so anyone can impersonate the host to a device that trusts it")
		}

		// Stage 2: key / server identity
		do {
			_ = try NIOSSLContext(configuration: try LocalTLSIdentity(
				source: source, certificateURL: crt, keyURL: key, hostname: hostname, report: report
			).tlsConfiguration())
			report.keyMatches = true
		} catch {
			report.problems.append("private key does not match the certificate or is unreadable (\(error))")
		}

		// Stage 3: structural check with an EXPLICIT anchor (informational, see file header).
		report.structural = structuralCheck(leafDER: der, hostname: hostname, now: now)
		return result()
	}

	/// Security.framework SSL-policy evaluation with an explicit anchor: the shipped CA if present,
	/// otherwise the leaf itself. Captures the full CFError metadata.
	static func structuralCheck(leafDER: [UInt8], hostname: String, now: Date = Date()) -> StructuralResult {
		guard let leaf = SecCertificateCreateWithData(nil, Data(leafDER) as CFData) else {
			return .init(passed: false, domain: nil, code: nil, message: "certificate DER could not be parsed by Security.framework", anchorDescription: "-")
		}
		var anchor = leaf
		var anchorDescription = "the leaf itself (no CA shipped)"
		if
			let url = anchorCertificateURL(),
			let pem = try? String(contentsOf: url, encoding: .utf8),
			let caDER = firstCertificateDER(fromPEM: pem),
			let ca = SecCertificateCreateWithData(nil, Data(caDER) as CFData)
		{
			anchor = ca
			anchorDescription = "CA \(fingerprint(of: caDER).prefix(23))…"
		}

		var trust: SecTrust?
		let status = SecTrustCreateWithCertificates(leaf, SecPolicyCreateSSL(true, hostname as CFString), &trust)
		guard status == errSecSuccess, let trust else {
			return .init(passed: false, domain: NSOSStatusErrorDomain, code: Int(status), message: "SecTrustCreateWithCertificates failed", anchorDescription: anchorDescription)
		}
		SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
		SecTrustSetAnchorCertificatesOnly(trust, true)
		SecTrustSetVerifyDate(trust, now as CFDate)
		var error: CFError?
		if SecTrustEvaluateWithError(trust, &error) {
			return .init(passed: true, domain: nil, code: nil, message: "accepted for \(hostname) with explicit anchor", anchorDescription: anchorDescription)
		}
		let ns = error.map { $0 as Error as NSError }
		return .init(passed: false, domain: ns?.domain, code: ns?.code, message: ns?.localizedDescription ?? "unknown", anchorDescription: anchorDescription)
	}

	// MARK: - Helpers

	/// RFC 6125 §6.4.3: a wildcard is only the whole left-most label and matches exactly one label.
	static func matches(pattern: String, hostname: String) -> Bool {
		let p = pattern.lowercased(), h = hostname.lowercased()
		guard p.hasPrefix("*.") else { return p == h }
		let suffix = p.dropFirst(1)              // ".backloop.dev"
		guard h.hasSuffix(suffix) else { return false }
		let label = h.dropLast(suffix.count)
		return !label.isEmpty && !label.contains(".")
	}

	static func firstCertificateDER(fromPEM pem: String) -> [UInt8]? {
		guard
			let begin = pem.range(of: "-----BEGIN CERTIFICATE-----"),
			let end = pem.range(of: "-----END CERTIFICATE-----", range: begin.upperBound..<pem.endIndex)
		else { return nil }
		let body = pem[begin.upperBound..<end.lowerBound]
			.components(separatedBy: .whitespacesAndNewlines)
			.joined()
		guard let data = Data(base64Encoded: body) else { return nil }
		return [UInt8](data)
	}

	static func fingerprint(of der: [UInt8]) -> String {
		SHA256.hash(data: Data(der)).map { String(format: "%02X", $0) }.joined(separator: ":")
	}
}

// MARK: - Minimal DER certificate reader (subject, issuer, SAN, validity)

struct DERCertificate {
	let subject: String
	let issuer: String
	let dnsNames: [String]
	let notBefore: Date
	let notAfter: Date
	let isSelfSigned: Bool

	static func parse(_ der: [UInt8]) -> DERCertificate? {
		var top = Reader(bytes: der)
		guard var cert = top.readSequence(), var tbs = cert.readSequence() else { return nil }

		if tbs.peekTag() == 0xA0 { _ = tbs.readElement() }       // [0] version
		guard
			tbs.readElement() != nil,                            // serialNumber
			tbs.readElement() != nil,                            // signature AlgorithmIdentifier
			let issuerEl = tbs.readElement(),                    // issuer Name
			var validity = tbs.readSequence(),
			let nb = validity.readTime(),
			let na = validity.readTime(),
			let subjectEl = tbs.readElement(),                   // subject Name
			tbs.readElement() != nil                             // subjectPublicKeyInfo
		else { return nil }

		var dns: [String] = []
		while let el = tbs.readElement() {
			guard el.tag == 0xA3 else { continue }               // [3] extensions
			var wrapper = Reader(bytes: Array(el.content))
			guard var extensions = wrapper.readSequence() else { break }
			while var ext = extensions.readSequence() {
				guard let oid = ext.readElement(), oid.tag == 0x06 else { continue }
				if ext.peekTag() == 0x01 { _ = ext.readElement() }   // critical BOOLEAN
				guard oid.content.elementsEqual([0x55, 0x1D, 0x11]), let value = ext.readElement(), value.tag == 0x04 else { continue }
				var inner = Reader(bytes: Array(value.content))
				guard var names = inner.readSequence() else { continue }
				while let name = names.readElement() {
					if name.tag == 0x82, let s = String(bytes: name.content, encoding: .ascii) { dns.append(s) }
				}
			}
		}

		return DERCertificate(
			subject: describe(name: Array(subjectEl.content)),
			issuer: describe(name: Array(issuerEl.content)),
			dnsNames: dns,
			notBefore: nb,
			notAfter: na,
			isSelfSigned: issuerEl.content.elementsEqual(subjectEl.content)
		)
	}

	/// "CN=…, O=…" from an X.501 Name, for display only.
	private static func describe(name: [UInt8]) -> String {
		var parts: [String] = []
		var rdns = Reader(bytes: name)
		while var rdn = rdns.readSet() {
			while var atv = rdn.readSequence() {
				guard let oid = atv.readElement(), let value = atv.readElement(), let s = String(bytes: value.content, encoding: .utf8) else { continue }
				let key: String
				switch Array(oid.content) {
				case [0x55, 0x04, 0x03]: key = "CN"
				case [0x55, 0x04, 0x0A]: key = "O"
				case [0x55, 0x04, 0x0B]: key = "OU"
				default: continue
				}
				parts.append("\(key)=\(s)")
			}
		}
		return parts.isEmpty ? "-" : parts.joined(separator: ", ")
	}

	struct Reader {
		let bytes: [UInt8]
		var pos = 0

		init(bytes: [UInt8]) { self.bytes = bytes }

		func peekTag() -> UInt8? { pos < bytes.count ? bytes[pos] : nil }

		mutating func readElement() -> (tag: UInt8, content: ArraySlice<UInt8>)? {
			guard pos + 2 <= bytes.count else { return nil }
			let tag = bytes[pos]; pos += 1
			var length = Int(bytes[pos]); pos += 1
			if length & 0x80 != 0 {
				let n = length & 0x7F
				guard n > 0, n <= 4, pos + n <= bytes.count else { return nil }
				length = 0
				for _ in 0..<n { length = (length << 8) | Int(bytes[pos]); pos += 1 }
			}
			guard pos + length <= bytes.count else { return nil }
			let content = bytes[pos..<(pos + length)]
			pos += length
			return (tag, content)
		}

		mutating func readSequence() -> Reader? {
			guard let e = readElement(), e.tag == 0x30 else { return nil }
			return Reader(bytes: Array(e.content))
		}

		mutating func readSet() -> Reader? {
			guard let e = readElement(), e.tag == 0x31 else { return nil }
			return Reader(bytes: Array(e.content))
		}

		mutating func readTime() -> Date? {
			guard let e = readElement(), e.tag == 0x17 || e.tag == 0x18 else { return nil }
			guard let s = String(bytes: e.content, encoding: .ascii) else { return nil }
			let f = DateFormatter()
			f.locale = Locale(identifier: "en_US_POSIX")
			f.timeZone = TimeZone(identifier: "UTC")
			f.dateFormat = e.tag == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
			return f.date(from: s)
		}
	}
}
