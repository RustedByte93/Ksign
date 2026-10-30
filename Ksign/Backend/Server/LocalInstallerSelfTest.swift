//
//  LocalInstallerSelfTest.swift
//  Ksign
//
//  Multi-stage diagnostic runner. Every stage ends as PASS, FAIL (it ran and failed) or NOT TESTED
//  (a prerequisite failed or it was out of scope). "Not reached" is never reported as "failed".
//
//  Client-side TLS verification is NEVER relaxed: the URLSession delegate records the presented chain and
//  the system trust verdict and then returns `.performDefaultHandling`.
//
//  What a PASS means: this app made a strictly validated HTTPS request to its own server. It does not prove
//  that iOS's installation service (installd / itunesstored) can do the same while Ksign is in the
//  background, and it never proves an installation. Stage "OTA installation" is therefore always NOT TESTED.
//

import Foundation
import CryptoKit
import Vapor
import NIOSSL

// MARK: - Model

enum StageID: String, CaseIterable, Codable {
	case dns, certificateLoaded, privateKeyMatch, certificateStandards, serverIdentity
	case httpsListener, presentedCertificate, systemTrust, health, manifest, ipaEndpoint, otaInstall

	var title: String {
		switch self {
		case .dns: return "DNS Resolution"
		case .certificateLoaded: return "Certificate Loaded"
		case .privateKeyMatch: return "Private Key Match"
		case .certificateStandards: return "Certificate Standards"
		case .serverIdentity: return "Server Identity Initialization"
		case .httpsListener: return "HTTPS Listener"
		case .presentedCertificate: return "Presented Certificate"
		case .systemTrust: return "System TLS Trust"
		case .health: return "GET /health"
		case .manifest: return "Manifest Endpoint"
		case .ipaEndpoint: return "IPA Endpoint"
		case .otaInstall: return "OTA Installation"
		}
	}
}

enum StageStatus: String, Codable { case pass = "PASS", fail = "FAIL", notTested = "NOT TESTED" }

struct StageResult: Codable, Identifiable {
	var id: StageID
	var status: StageStatus
	var detail: String
	var errorDomain: String?
	var errorCode: Int?
	var nextAction: String?

	static func notTested(_ id: StageID, _ reason: String) -> StageResult { .init(id: id, status: .notTested, detail: reason) }
}

// MARK: - HTTPS probe (strict validation, records evidence)

struct ProbeResult {
	var status: Int?
	var headers: [String: String] = [:]
	var body = Data()
	var error: NSError?
	var challengeReached = false
	var presentedFingerprint: String?
	var trustPassed: Bool?
	var trustDomain: String?
	var trustCode: Int?
	var trustMessage: String?
	var milliseconds = 0
}

private final class TrustRecordingDelegate: NSObject, URLSessionDelegate {
	var result = ProbeResult()

	func urlSession(
		_ session: URLSession,
		didReceive challenge: URLAuthenticationChallenge,
		completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
	) {
		if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
		   let trust = challenge.protectionSpace.serverTrust {
			result.challengeReached = true
			if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
				result.presentedFingerprint = LocalTLSIdentity.fingerprint(of: [UInt8](SecCertificateCopyData(leaf) as Data))
			}
			var error: CFError?
			if SecTrustEvaluateWithError(trust, &error) {
				result.trustPassed = true
			} else {
				let ns = error.map { $0 as Error as NSError }
				result.trustPassed = false
				result.trustDomain = ns?.domain
				result.trustCode = ns?.code
				result.trustMessage = ns?.localizedDescription
			}
		}
		completionHandler(.performDefaultHandling, nil)
	}
}

enum HTTPSProbe {
	static func get(_ url: URL, headers: [String: String] = [:], timeout: TimeInterval = 15, operation: String = "-") -> ProbeResult {
		let diag = LocalInstallerDiagnostics.shared
		let host = url.host, port = url.port
		diag.log(component: "client.tls", event: "tls.handshake.attempt", message: "GET \(url.path) (default system trust)", operation: operation, hostname: host, port: port)

		let delegate = TrustRecordingDelegate()
		let config = URLSessionConfiguration.ephemeral
		config.requestCachePolicy = .reloadIgnoringLocalCacheData
		let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
		defer { session.invalidateAndCancel() }

		var request = URLRequest(url: url)
		request.timeoutInterval = timeout
		headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }

		let started = Date()
		let semaphore = DispatchSemaphore(value: 0)
		var status: Int?, responseHeaders: [String: String] = [:], body = Data(), error: NSError?
		session.dataTask(with: request) { data, response, err in
			error = err as NSError?
			if let http = response as? HTTPURLResponse {
				status = http.statusCode
				for (k, v) in http.allHeaderFields { responseHeaders["\(k)".lowercased()] = "\(v)" }
			}
			body = data ?? Data()
			semaphore.signal()
		}.resume()
		_ = semaphore.wait(timeout: .now() + timeout + 5)

		var result = delegate.result
		result.status = status
		result.headers = responseHeaders
		result.body = body
		result.error = error
		result.milliseconds = Int(Date().timeIntervalSince(started) * 1000)

		if let error {
			diag.log(component: "client.tls", event: "tls.handshake.failed", message: "request failed after \(result.milliseconds) ms", level: .error, operation: operation, error: error, hostname: host, port: port,
					 metadata: ["presentedFingerprint": result.presentedFingerprint ?? "-", "challengeReached": "\(result.challengeReached)"])
		} else {
			diag.log(component: "client.tls", event: "tls.handshake.completed", message: "HTTP \(status ?? 0) in \(result.milliseconds) ms; system trust accepted", operation: operation, hostname: host, port: port,
					 metadata: ["presentedFingerprint": result.presentedFingerprint ?? "-"])
		}
		return result
	}

	/// Next step for a client-side certificate failure. Keyed on the real error, not guessed.
	static func advice(domain: String?, code: Int?, validityDays: Int?) -> String {
		switch code {
		case -67901:
			return "The leaf is valid for \(validityDays.map(String.init) ?? "more than 825") days; Apple rejects TLS server certificates valid longer than \(LocalTLSIdentity.appleMaximumValidityDays) days. Regenerate with Scripts/make-local-pki.sh (default 365 days) and rebuild."
		case -25318, -9807, NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot:
			return "iOS does not trust this certificate's CA. Install KsignLocalCA.mobileconfig (Diagnostics ▸ Export Trust Profile), then enable it in Settings ▸ General ▸ About ▸ Certificate Trust Settings."
		case -67602, NSURLErrorServerCertificateHasBadDate, NSURLErrorServerCertificateNotYetValid:
			return "Check the device date/time and that the certificate's SAN lists the hostname."
		case -67689:
			return "The certificate or its CA violates a standard (name constraints, key usage or EKU). Regenerate with Scripts/make-local-pki.sh."
		default:
			return "See the error domain/code above and the event log."
		}
	}
}

// MARK: - Runner

enum LocalInstallerSelfTest {
	enum Scope: String {
		case full, certificate, listener, systemTrust, manifest, ipa

		var lastStage: StageID {
			switch self {
			case .certificate: return .serverIdentity
			case .listener: return .presentedCertificate
			case .systemTrust: return .systemTrust
			case .manifest: return .manifest
			case .ipa: return .ipaEndpoint
			case .full: return .otaInstall
			}
		}
	}

	static func run(scope: Scope) async -> [StageResult] {
		await Task.detached(priority: .userInitiated) { Run(scope: scope).execute() }.value
	}

	/// Used as the install gate: a strict HTTPS request to the REAL running installer. Returns nil on success,
	/// otherwise a user-presentable explanation including the next action.
	static func verifyInstallerTrust(host: String, port: Int, operation: String) async -> String? {
		await Task.detached(priority: .userInitiated) { () -> String? in
			guard let url = URL(string: "https://\(host):\(port)/health") else { return "invalid installer URL" }
			let r = HTTPSProbe.get(url, timeout: 8, operation: operation)
			if r.error == nil, r.status == 200, r.trustPassed == true { return nil }
			let days = LocalTLSIdentity.inspectCurrent()?.report.validityDays
			if r.trustPassed == false {
				return "iOS rejected the local server certificate: \(r.trustMessage ?? "unknown") [\(r.trustDomain ?? "?") \(r.trustCode.map(String.init) ?? "?")].\n\n" + HTTPSProbe.advice(domain: r.trustDomain, code: r.trustCode, validityDays: days)
			}
			if let e = r.error {
				return "Could not reach the local server over HTTPS: \(e.localizedDescription) [\(e.domain) \(e.code)].\n\n" + HTTPSProbe.advice(domain: e.domain, code: e.code, validityDays: days)
			}
			return "Unexpected response from the local server (HTTP \(r.status.map(String.init) ?? "none"))."
		}.value
	}

	// MARK: Implementation

	private final class Run {
		let scope: Scope
		let op = "T-" + UUID().uuidString.prefix(8)
		let diag = LocalInstallerDiagnostics.shared
		var results: [StageID: StageResult] = [:]
		var host = LocalTLSIdentity.resolveHostname()
		var identity: LocalTLSIdentity?
		var app: Application?
		var port = 0
		var fixtureIPA: URL?
		var trusted = false

		init(scope: Scope) { self.scope = scope }

		func set(_ id: StageID, _ status: StageStatus, _ detail: String, error: (String?, Int?)? = nil, next: String? = nil) {
			results[id] = StageResult(id: id, status: status, detail: detail, errorDomain: error?.0, errorCode: error?.1, nextAction: next)
			diag.log(component: "selftest", event: "selftest.stage.\(id.rawValue)", message: "\(status.rawValue): \(detail)",
					 level: status == .fail ? .error : .info, operation: op, hostname: host, port: port == 0 ? nil : port)
		}

		func wants(_ id: StageID) -> Bool {
			(StageID.allCases.firstIndex(of: id) ?? 0) <= (StageID.allCases.firstIndex(of: scope.lastStage) ?? 0)
		}

		func execute() -> [StageResult] {
			diag.setPipeline("self-test")
			diag.log(component: "selftest", event: "selftest.started", message: "scope=\(scope.rawValue)", operation: op, hostname: host)
			defer {
				stopServer()
				if let fixtureIPA { try? FileManager.default.removeItem(at: fixtureIPA) }
				diag.setPipeline("idle")
				diag.log(component: "selftest", event: "selftest.finished", message: "scope=\(scope.rawValue)", operation: op)
			}

			stageDNS()
			stageCertificate()
			stageServerIdentity()
			stageListener()
			stageTLS()
			stageEndpoints()
			if wants(.otaInstall) {
				set(.otaInstall, .notTested, "Only iOS can confirm an installation. This app cannot observe installd. After tapping Install, check Last IPA request and the transfer events.",
					next: "Install a real signed IPA, then open the event log and look for http.ipa.* events.")
			}
			return StageID.allCases.map { results[$0] ?? .notTested($0, "not part of this test (run Full Diagnostics)") }
		}

		// 1
		func stageDNS() {
			guard wants(.dns) else { return }
			let addrs = Self.resolve(host: host)
			if addrs.isEmpty {
				set(.dns, .fail, "\(host) did not resolve", next: "Disable VPN / private DNS / DNS filtering for backloop.dev, or allow the name to resolve to 127.0.0.1.")
			} else if !addrs.contains("127.0.0.1") {
				set(.dns, .fail, "\(host) → \(addrs.joined(separator: ", ")) (no 127.0.0.1; the Fully Local server listens on IPv4 loopback only)",
					next: "A resolver is rewriting \(host). Use a resolver that returns 127.0.0.1.")
			} else {
				let v6 = addrs.contains(where: { $0.contains(":") }) ? "IPv6 \(addrs.filter { $0.contains(":") }.joined(separator: ", ")) is also returned but not listened on" : "no IPv6 record"
				set(.dns, .pass, "\(host) → \(addrs.joined(separator: ", ")); \(v6)")
			}
		}

		// 2, 3, 4
		func stageCertificate() {
			guard wants(.certificateLoaded) else { return }
			guard let id = LocalTLSIdentity.inspectCurrent() else {
				set(.certificateLoaded, .fail, "No server.crt/server.pem in the app bundle or Documents/App/Server/custom/",
					next: "Rebuild the app with `make` (runs Scripts/make-local-pki.sh) or supply a custom identity.")
				return
			}
			identity = id
			let r = id.report
			guard r.parsed else {
				set(.certificateLoaded, .fail, r.problems.joined(separator: "; "), next: "The certificate file must be a PEM X.509 certificate.")
				return
			}
			let df = ISO8601DateFormatter()
			set(.certificateLoaded, .pass, """
				source: \(id.source.rawValue)
				subject: \(r.subject)
				issuer: \(r.issuer)\(r.isSelfSigned ? " (self-signed)" : "")
				SAN: \(r.subjectAltNames.isEmpty ? "(none)" : r.subjectAltNames.joined(separator: ", ")) – covers \(id.hostname): \(r.hostnameInSAN)
				valid: \(r.notBefore.map { df.string(from: $0) } ?? "-") → \(r.notAfter.map { df.string(from: $0) } ?? "-") (\(r.validityDays.map(String.init) ?? "?") days)
				SHA-256: \(r.fingerprint)
				""")

			guard wants(.privateKeyMatch) else { return }
			if r.keyMatches {
				set(.privateKeyMatch, .pass, "BoringSSL accepted the certificate/key pair")
			} else {
				set(.privateKeyMatch, .fail, r.problems.first(where: { $0.contains("private key") }) ?? "key does not match",
					next: "Regenerate the pair together with Scripts/make-local-pki.sh.")
			}

			guard wants(.certificateStandards) else { return }
			var extra = r.warnings.isEmpty ? "" : "\nwarnings: " + r.warnings.joined(separator: "; ")
			if r.isExpired || r.isNotYetValid { extra = "\n" + r.problems.joined(separator: "; ") + extra }
			if let s = r.structural {
				if s.passed && !r.isExpired && !r.isNotYetValid {
					set(.certificateStandards, .pass, "Security.framework SSL policy accepted the leaf for \(id.hostname) against explicit anchor \(s.anchorDescription). This is a structure check, not device trust.\(extra)")
				} else {
					set(.certificateStandards, .fail, "\(s.message) [\(s.domain ?? "-") \(s.code.map(String.init) ?? "-")] (anchor: \(s.anchorDescription))\(extra)",
						error: (s.domain, s.code),
						next: HTTPSProbe.advice(domain: s.domain, code: s.code, validityDays: r.validityDays))
				}
			}
		}

		// 5
		func stageServerIdentity() {
			guard wants(.serverIdentity) else { return }
			guard let id = identity, id.report.parsed else {
				set(.serverIdentity, .notTested, "no certificate loaded (see Certificate Loaded)")
				return
			}
			guard id.report.isUsable else {
				set(.serverIdentity, .notTested, "identity not usable by the server: \(id.report.problems.joined(separator: "; "))")
				return
			}
			do {
				_ = try NIOSSLContext(configuration: try id.tlsConfiguration())
				set(.serverIdentity, .pass, "TLS server configuration built (TLS ≥ 1.2) with this identity")
			} catch {
				set(.serverIdentity, .fail, "\(error)", error: ((error as NSError).domain, (error as NSError).code), next: "Replace the certificate/key pair.")
			}
		}

		// 6
		func stageListener() {
			guard wants(.httpsListener) else { return }
			guard results[.serverIdentity]?.status == .pass, let id = identity else {
				set(.httpsListener, .notTested, "server identity not initialized")
				return
			}
			let fixture = FileManager.default.temporaryDirectory.appendingPathComponent("ksign-selftest-\(op).ipa")
			var bytes = [UInt8](repeating: 0, count: 3 * 1024 * 1024)
			for i in 0..<bytes.count { bytes[i] = UInt8(truncatingIfNeeded: i &* 31 &+ (i >> 8)) }
			guard (try? Data(bytes).write(to: fixture)) != nil else {
				set(.httpsListener, .fail, "could not write the test fixture to the temporary directory")
				return
			}
			fixtureIPA = fixture

			var lastError: Error?
			for attempt in 1...5 {
				let candidate = Int.random(in: 20000...40000)
				diag.log(component: "selftest", event: "server.bind.attempt", message: "binding 127.0.0.1:\(candidate) (attempt \(attempt))", operation: op, port: candidate)
				do {
					let server = try ServerInstaller.setupApp(port: candidate, forceTLSIdentity: id)
					let hostForManifest = host
					server.get("health") { _ in "ok" }
					server.get("fixture.plist") { req in
						let data = try LocalInstallerManifest.make(
							bundleIdentifier: "dev.ksign.selftest", bundleVersion: "1.0", title: "Self-test",
							packageURL: URL(string: "https://\(hostForManifest):\(candidate)/fixture.ipa")!,
							displayImageURL: URL(string: "https://\(hostForManifest):\(candidate)/app57x57.png")!
						)
						return Response(status: .ok, headers: ["Content-Type": "text/xml"], body: .init(data: data))
					}
					server.get("fixture.ipa") { req in IPAResponder.response(for: req, fileURL: fixture) }
					try server.server.start()
					app = server
					port = candidate
					diag.log(component: "selftest", event: "server.listener.started", message: "listening on 127.0.0.1:\(candidate) (diagnostic server)", operation: op, hostname: host, port: candidate)
					set(.httpsListener, .pass, "bound 127.0.0.1:\(candidate) (IPv4 loopback; IPv6 not bound by design); diagnostic server only")
					return
				} catch {
					lastError = error
					diag.log(component: "selftest", event: "server.listener.failed", message: "bind failed", level: .error, operation: op, error: error, port: candidate)
				}
			}
			set(.httpsListener, .fail, "\(lastError?.localizedDescription ?? "unknown")", error: ((lastError as NSError?)?.domain, (lastError as NSError?)?.code),
				next: "Another process may hold the ports, or Local Network / sandbox restrictions apply. Retry.")
		}

		// 7, 8, 9
		func stageTLS() {
			guard wants(.presentedCertificate) else { return }
			guard app != nil, port != 0 else {
				for s in [StageID.presentedCertificate, .systemTrust, .health] where wants(s) { set(s, .notTested, "HTTPS listener not running") }
				return
			}
			guard results[.dns]?.status == .pass else {
				for s in [StageID.presentedCertificate, .systemTrust, .health] where wants(s) { set(s, .notTested, "\(host) does not resolve to 127.0.0.1, so a client cannot reach the listener by name (see DNS Resolution)") }
				return
			}
			let r = HTTPSProbe.get(URL(string: "https://\(host):\(port)/health")!, operation: op)

			if let fp = r.presentedFingerprint {
				let expected = identity?.report.fingerprint
				if fp == expected {
					set(.presentedCertificate, .pass, "server presented the expected certificate \(fp) for SNI \(host)")
				} else {
					set(.presentedCertificate, .fail, "presented \(fp), expected \(expected ?? "-")", next: "The listener is not using the identity shown in Certificate Loaded.")
				}
			} else {
				let e = r.error
				set(.presentedCertificate, .fail, "no certificate was received: \(e?.localizedDescription ?? "no TLS challenge") [\(e?.domain ?? "-") \(e?.code.description ?? "-")]",
					error: (e?.domain, e?.code), next: "The TLS handshake did not reach certificate presentation. Check the listener and any VPN/proxy.")
			}

			guard wants(.systemTrust) else { return }
			if r.trustPassed == true {
				trusted = true
				set(.systemTrust, .pass, "default iOS trust evaluation (SecTrustEvaluateWithError) accepted the chain for \(host)")
			} else if r.trustPassed == false {
				set(.systemTrust, .fail, "\(r.trustMessage ?? "unknown") [\(r.trustDomain ?? "-") \(r.trustCode.map(String.init) ?? "-")]",
					error: (r.trustDomain, r.trustCode),
					next: HTTPSProbe.advice(domain: r.trustDomain, code: r.trustCode, validityDays: identity?.report.validityDays))
			} else {
				set(.systemTrust, .notTested, "no trust evaluation happened (no TLS challenge was reached)")
			}

			guard wants(.health) else { return }
			if !trusted {
				set(.health, .notTested, "blocked: HTTPS is not trusted, and verification is never bypassed")
			} else if r.status == 200, String(data: r.body, encoding: .utf8) == "ok" {
				set(.health, .pass, "HTTP 200 \"ok\" in \(r.milliseconds) ms")
			} else {
				set(.health, .fail, "unexpected response: HTTP \(r.status.map(String.init) ?? "none"), error \(r.error?.localizedDescription ?? "-")")
			}
		}

		// 10, 11
		func stageEndpoints() {
			guard wants(.manifest) else { return }
			guard trusted else {
				for s in [StageID.manifest, .ipaEndpoint] where wants(s) { set(s, .notTested, "blocked: no trusted HTTPS connection") }
				return
			}
			let base = "https://\(host):\(port)"

			let m = HTTPSProbe.get(URL(string: "\(base)/fixture.plist")!, operation: op)
			if m.status == 200, (m.headers["content-type"] ?? "").contains("xml") {
				let v = LocalInstallerManifest.validate(m.body, expectedHost: host, expectedPort: port)
				if v.isValid {
					set(.manifest, .pass, "HTTP 200 text/xml; schema valid; package URL \(v.packageURL?.absoluteString ?? "-") uses the bound port \(port) (fixture manifest, not your IPA)")
				} else {
					set(.manifest, .fail, v.errors.joined(separator: "; "), next: "Manifest generation is wrong; see LocalInstallerManifest.")
				}
			} else {
				set(.manifest, .fail, "HTTP \(m.status.map(String.init) ?? "none") content-type \(m.headers["content-type"] ?? "-")")
			}

			guard wants(.ipaEndpoint), let fixtureIPA, let data = try? Data(contentsOf: fixtureIPA) else { return }
			var problems: [String] = []
			let full = HTTPSProbe.get(URL(string: "\(base)/fixture.ipa")!, operation: op)
			if full.status != 200 { problems.append("full GET → HTTP \(full.status.map(String.init) ?? "none")") }
			if full.headers["content-length"] != String(data.count) { problems.append("Content-Length \(full.headers["content-length"] ?? "-") ≠ \(data.count)") }
			if full.headers["accept-ranges"] != "bytes" { problems.append("Accept-Ranges missing") }
			if !(full.headers["content-type"] ?? "").contains("application/octet-stream") { problems.append("Content-Type \(full.headers["content-type"] ?? "-")") }
			if SHA256.hash(data: full.body) != SHA256.hash(data: data) { problems.append("body hash differs") }

			let part = HTTPSProbe.get(URL(string: "\(base)/fixture.ipa")!, headers: ["Range": "bytes=1000-1999"], operation: op)
			if part.status != 206 { problems.append("Range → HTTP \(part.status.map(String.init) ?? "none"), expected 206") }
			if part.headers["content-range"] != "bytes 1000-1999/\(data.count)" { problems.append("Content-Range \(part.headers["content-range"] ?? "-")") }
			if part.body != data.subdata(in: 1000..<2000) { problems.append("range body differs") }

			let bad = HTTPSProbe.get(URL(string: "\(base)/fixture.ipa")!, headers: ["Range": "bytes=\(data.count + 10)-"], operation: op)
			if bad.status != 416 { problems.append("unsatisfiable Range → HTTP \(bad.status.map(String.init) ?? "none"), expected 416") }

			if problems.isEmpty {
				set(.ipaEndpoint, .pass, "3 MB fixture: 200 with exact Content-Length and matching SHA-256; 206 Content-Range correct; 416 for unsatisfiable range. Large-file streaming is covered by Tests/LocalInstaller, not here.")
			} else {
				set(.ipaEndpoint, .fail, problems.joined(separator: "; "), next: "IPA streaming (IPAResponder) misbehaves; see the event log.")
			}
		}

		func stopServer() {
			guard let app else { return }
			app.server.shutdown()
			app.shutdown()
			self.app = nil
			diag.log(component: "selftest", event: "server.stopped", message: "diagnostic server stopped", operation: op, port: port)
		}

		static func resolve(host: String) -> [String] {
			var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM
			var res: UnsafeMutablePointer<addrinfo>?
			guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
			defer { freeaddrinfo(res) }
			var out: [String] = []
			var p: UnsafeMutablePointer<addrinfo>? = first
			while let a = p {
				var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
				if getnameinfo(a.pointee.ai_addr, a.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
					let s = String(cString: buf)
					if !out.contains(s) { out.append(s) }
				}
				p = a.pointee.ai_next
			}
			return out
		}
	}
}
