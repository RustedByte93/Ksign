import XCTest
import Vapor
@testable import LocalInstallerCore

private let skipLarge = ProcessInfo.processInfo.environment["KSIGN_SKIP_LARGE"] == "1"
private let host = "ksign.backloop.dev"

final class TLSTests: XCTestCase {
	func testPrivatePKIStrictHandshake() throws {
		let pki = try PKI.generate()
		defer { try? FileManager.default.removeItem(at: pki.dir) }
		let server = try TestServer(files: [:], tls: (pki.crt, pki.key))
		defer { server.shutdown() }
		let p = server.port

		// 1. Strict verification against the private CA, SNI = hostname.
		let ok = sh("curl -sS --cacert \(q(pki.ca)) --resolve \(host):\(p):127.0.0.1 -w ' [%{http_code}]' https://\(host):\(p)/health")
		XCTAssertEqual(ok.status, 0, ok.err)
		XCTAssertEqual(ok.out, "ok [200]")

		// 2. Same request without the CA: must fail with a certificate error (nothing is bypassed).
		let noCA = sh("curl -sS --resolve \(host):\(p):127.0.0.1 https://\(host):\(p)/health")
		XCTAssertNotEqual(noCA.status, 0)
		XCTAssertTrue([60, 35].contains(noCA.status), "expected certificate failure (60), got \(noCA.status): \(noCA.err)")

		// 3. Wrong hostname with the CA: must fail.
		let wrong = sh("curl -sS --cacert \(q(pki.ca)) --resolve evil.example.com:\(p):127.0.0.1 https://evil.example.com:\(p)/health")
		XCTAssertNotEqual(wrong.status, 0)
		XCTAssertEqual(wrong.status, 60, wrong.err)

		// 4. openssl s_client: verify code and presented leaf.
		let s = sh("echo | openssl s_client -connect 127.0.0.1:\(p) -servername \(host) -CAfile \(q(pki.ca)) -verify_hostname \(host) 2>&1")
		print("S_CLIENT_REPORT:\n" + s.out.split(separator: "\n").filter { $0.contains("Verify return code") || $0.contains("Protocol") || $0.contains("Cipher is") || $0.contains("Verification") }.joined(separator: "\n"))
		XCTAssertTrue(s.out.contains("Verify return code: 0 (ok)"), s.out)
		let presented = sh("echo | openssl s_client -connect 127.0.0.1:\(p) -servername \(host) 2>/dev/null | openssl x509 -noout -fingerprint -sha256").out
		let onDisk = sh("openssl x509 -in \(q(pki.crt)) -noout -fingerprint -sha256").out
		XCTAssertFalse(presented.isEmpty)
		XCTAssertEqual(presented, onDisk, "presented leaf differs from server.crt")
		print("S_CLIENT_REPORT presented \(presented)")
	}

	func testTLS12MinimumIsEnforced() throws {
		let pki = try PKI.generate()
		defer { try? FileManager.default.removeItem(at: pki.dir) }
		let server = try TestServer(files: [:], tls: (pki.crt, pki.key))
		defer { server.shutdown() }
		let ok = sh("echo | openssl s_client -connect 127.0.0.1:\(server.port) -servername \(host) -tls1_2 2>&1")
		XCTAssertTrue(ok.out.contains("TLSv1.2"), "TLS 1.2 must be accepted: \(ok.out.prefix(400))")
		// Note: s_client prints "Verify return code: 0" even when no handshake happened, so check the negotiated protocol instead.
		let old = sh("echo | openssl s_client -connect 127.0.0.1:\(server.port) -servername \(host) -min_protocol TLSv1 -max_protocol TLSv1.1 -cipher 'DEFAULT:@SECLEVEL=0' 2>&1")
		print("TLS11_REPORT \(old.out.split(separator: "\n").first(where: { $0.contains("error") || $0.contains("alert") || $0.contains("no peer") }) ?? "no error line")")
		XCTAssertFalse(old.out.contains("Server certificate"), "TLS <= 1.1 must be refused: \(old.out.prefix(400))")
		XCTAssertTrue(old.out.contains("alert protocol version") || old.out.contains("no peer certificate"), "expected a protocol-version refusal: \(old.out.prefix(400))")
	}

	func testLargeRangeOverTLS() throws {
		try XCTSkipIf(skipLarge, "KSIGN_SKIP_LARGE=1")
		let pki = try PKI.generate()
		defer { try? FileManager.default.removeItem(at: pki.dir) }
		let src = Fixtures.large(megabytes: 250)
		let total = Int64(250) << 20
		let server = try TestServer(files: ["big.ipa": src], tls: (pki.crt, pki.key))
		defer { server.shutdown() }
		let p = server.port
		let offset = total - 100_000_000
		let out = Fixtures.dir.appendingPathComponent("tls-tail.out").path
		let start = Date()
		let (r, peak) = withRSSSampling {
			sh("curl -sS --cacert \(q(pki.ca)) --resolve \(host):\(p):127.0.0.1 -H 'Range: bytes=\(offset)-' -o \(q(out)) -w '%{http_code} %{size_download}' https://\(host):\(p)/file/big.ipa")
		}
		print("RSS_REPORT 250MB TLS range (100 MB): peak RSS growth \(String(format: "%.1f", peak)) MB, \(String(format: "%.1f", Date().timeIntervalSince(start))) s")
		XCTAssertEqual(r.out, "206 100000000", r.err)
		XCTAssertEqual(sha256(file: out), sha256(file: src.path, offset: offset, length: 100_000_000))
		try? FileManager.default.removeItem(atPath: out)
	}

	/// The published backloop.dev certificate (10-year validity) is acceptable to OpenSSL. Apple's
	/// Security.framework rejects it (errSecCertificateValidityPeriodTooLong, -67901); see the Swift harness
	/// in LOCAL_INSTALLER.md. This test documents that the failure is specific to Apple's trust evaluation.
	func testPublicBackloopCertIsAcceptedByOpenSSL() throws {
		let pub = try XCTUnwrap(PublicCert.extract(), "packages/Ksign-previous-public-cert.ipa not present")
		defer { try? FileManager.default.removeItem(at: pub.dir) }
		let crt = pub.crt, key = pub.key
		let server = try TestServer(files: [:], tls: (crt, key))
		defer { server.shutdown() }
		let s = sh("echo | openssl s_client -connect 127.0.0.1:\(server.port) -servername \(host) -CAfile \(q(crt)) -verify_hostname \(host) 2>&1")
		XCTAssertTrue(s.out.contains("Verify return code: 0 (ok)"), s.out)
		let days = sh("openssl x509 -in \(q(crt)) -noout -checkend \(826 * 86400)").status
		XCTAssertEqual(days, 0, "cert is expected to be valid for more than 825 days (the property Apple rejects)")
	}
}
