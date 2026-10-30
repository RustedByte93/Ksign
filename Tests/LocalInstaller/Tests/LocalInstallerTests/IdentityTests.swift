import XCTest
import Foundation
@testable import LocalInstallerCore

/// The real published backloop.dev certificate, extracted from the previous IPA into a temp dir (never into the repo).
enum PublicCert {
	struct Files { let dir: URL; var crt: String { dir.appendingPathComponent("server.crt").path }; var key: String { dir.appendingPathComponent("server.pem").path } }
	static func extract() -> Files? {
		let ipa = repoRoot().appendingPathComponent("packages/Ksign-previous-public-cert.ipa").path
		guard FileManager.default.fileExists(atPath: ipa) else { return nil }
		let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ksign-pub-\(UUID().uuidString)")
		try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
		let r = sh("unzip -q -o -j \(q(ipa)) 'Payload/Ksign.app/server.crt' 'Payload/Ksign.app/server.pem' -d \(q(dir.path))")
		guard r.status == 0 else { return nil }
		return Files(dir: dir)
	}
}

final class IdentityTests: XCTestCase {
	let host = "ksign.backloop.dev"
	var tmp: URL!
	var pki: PKI!

	override func setUpWithError() throws {
		tmp = FileManager.default.temporaryDirectory.appendingPathComponent("ksign-id-\(UUID().uuidString)")
		try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
		pki = try PKI.generate()
		LocalTLSIdentity.anchorCertificateOverride = nil
	}
	override func tearDown() {
		LocalTLSIdentity.anchorCertificateOverride = nil
		try? FileManager.default.removeItem(at: tmp)
		if let pki { try? FileManager.default.removeItem(at: pki.dir) }
	}

	private func inspect(_ crt: String, _ key: String, host: String? = nil, now: Date = Date()) -> LocalTLSIdentity {
		LocalTLSIdentity.inspect(source: .custom, crt: URL(fileURLWithPath: crt), key: URL(fileURLWithPath: key), hostname: host ?? self.host, now: now)
	}

	private func selfSigned3650() throws -> (crt: String, key: String) {
		let crt = tmp.appendingPathComponent("long.crt").path, key = tmp.appendingPathComponent("long.pem").path
		let r = sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout \(q(key)) -out \(q(crt)) -days 3650 -sha256 -subj '/CN=*.backloop.dev/O=backloop.dev' -addext 'subjectAltName=DNS:*.backloop.dev,DNS:backloop.dev' -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment' -addext 'extendedKeyUsage=serverAuth' 2>&1")
		XCTAssertEqual(r.status, 0, r.out + r.err)
		return (crt, key)
	}

	// 1
	func testPrivatePKILeafIsFullyAcceptable() {
		LocalTLSIdentity.anchorCertificateOverride = URL(fileURLWithPath: pki.ca)
		let r = inspect(pki.crt, pki.key).report
		XCTAssertTrue(r.parsed)
		XCTAssertTrue(r.subject.contains("CN=ksign.backloop.dev"), r.subject)
		XCTAssertTrue(r.issuer.contains("CN=Ksign Local Installer CA"), r.issuer)
		XCTAssertFalse(r.isSelfSigned)
		XCTAssertEqual(r.subjectAltNames, ["ksign.backloop.dev"])
		XCTAssertEqual(Double(r.validityDays ?? 0), 365, accuracy: 1)
		XCTAssertTrue(r.keyMatches)
		XCTAssertTrue(r.hostnameInSAN)
		XCTAssertEqual(r.structural?.passed, true, r.structural?.message ?? "nil")
		XCTAssertTrue(r.isUsable)
		XCTAssertTrue(r.problems.isEmpty, "\(r.problems)")
		XCTAssertTrue(r.warnings.isEmpty, "\(r.warnings)")
		XCTAssertFalse(r.isSharedPublicKey)
	}

	// 2
	func testLeafAsOwnAnchorIsReportedWithoutCrash() {
		let r = inspect(pki.crt, pki.key).report
		XCTAssertNotNil(r.structural)
		XCTAssertTrue(r.structural?.anchorDescription.contains("leaf") == true, r.structural?.anchorDescription ?? "")
		print("LEAF_AS_ANCHOR structural passed=\(r.structural?.passed ?? false) \(r.structural?.message ?? "")")
	}

	// 3
	func testTenYearWildcardFailsAppleStructureCheckButServerStaysUsable() throws {
		let (crt, key) = try selfSigned3650()
		let r = inspect(crt, key).report
		XCTAssertEqual(r.structural?.passed, false)
		XCTAssertEqual(r.structural?.code, -67901)
		XCTAssertEqual(r.structural?.domain, NSOSStatusErrorDomain)
		XCTAssertEqual(Double(r.validityDays ?? 0), 3650, accuracy: 2)
		XCTAssertTrue(r.warnings.contains { $0.contains("825") }, "\(r.warnings)")
		XCTAssertTrue(r.isSelfSigned)
		XCTAssertTrue(r.hostnameInSAN)
		XCTAssertTrue(r.isUsable, "the standards check must not block server startup: \(r.problems)")
	}

	func testRealPublishedBackloopCert() throws {
		let pub = try XCTUnwrap(PublicCert.extract(), "packages/Ksign-previous-public-cert.ipa not present")
		defer { try? FileManager.default.removeItem(at: pub.dir) }
		let r = inspect(pub.crt, pub.key).report
		XCTAssertTrue(r.isSharedPublicKey)
		XCTAssertEqual(r.fingerprint, LocalTLSIdentity.publicBackloopFingerprint)
		XCTAssertEqual(r.structural?.code, -67901)
		XCTAssertTrue(r.isUsable)
	}

	// 4
	func testWrongKeyIsNotUsable() throws {
		let other = tmp.appendingPathComponent("other.pem").path
		XCTAssertEqual(sh("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out \(q(other))").status, 0)
		let r = inspect(pki.crt, other).report
		XCTAssertFalse(r.keyMatches)
		XCTAssertFalse(r.isUsable)
		XCTAssertTrue(r.problems.contains { $0.contains("private key") }, "\(r.problems)")
	}

	func testExpiredAndNotYetValid() {
		let future = inspect(pki.crt, pki.key, now: Date().addingTimeInterval(800 * 86400)).report
		XCTAssertTrue(future.isExpired)
		XCTAssertFalse(future.problems.isEmpty)
		XCTAssertFalse(future.isUsable)
		let past = inspect(pki.crt, pki.key, now: Date().addingTimeInterval(-30 * 86400)).report
		XCTAssertTrue(past.isNotYetValid)
		XCTAssertFalse(past.isUsable)
	}

	// 5
	func testWrongHostname() {
		LocalTLSIdentity.anchorCertificateOverride = URL(fileURLWithPath: pki.ca)
		let r = inspect(pki.crt, pki.key, host: "evil.example.com").report
		XCTAssertFalse(r.hostnameInSAN)
		XCTAssertTrue(r.warnings.contains { $0.contains("SAN") }, "\(r.warnings)")
		XCTAssertEqual(r.structural?.passed, false)
		print("WRONG_HOST structural code=\(r.structural?.code ?? 0) \(r.structural?.message ?? "")")
	}

	// 6
	func testWildcardMatching() {
		let m = LocalTLSIdentity.matches(pattern:hostname:)
		XCTAssertTrue(m("*.backloop.dev", "ksign.backloop.dev"))
		XCTAssertFalse(m("*.backloop.dev", "backloop.dev"))
		XCTAssertFalse(m("*.backloop.dev", "a.b.backloop.dev"))
		XCTAssertTrue(m("ksign.backloop.dev", "ksign.backloop.dev"))
		XCTAssertFalse(m("ksign.backloop.dev", "other.backloop.dev"))
		XCTAssertTrue(m("*.BackLoop.DEV", "KSIGN.backloop.dev"))
		XCTAssertFalse(m("*.backloop.dev", "evilbackloop.dev"))
	}

	// 7
	func testNameConstraintViolationIsRejected() throws {
		let ca = pki.dir.appendingPathComponent("pki/ca.crt").path, caKey = pki.dir.appendingPathComponent("pki/ca.key").path
		let key = tmp.appendingPathComponent("o.key").path, csr = tmp.appendingPathComponent("o.csr").path
		let ext = tmp.appendingPathComponent("o.ext").path, crt = tmp.appendingPathComponent("o.crt").path
		try "subjectAltName=DNS:other.example.com\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n".write(toFile: ext, atomically: true, encoding: .utf8)
		let r = sh("openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout \(q(key)) -out \(q(csr)) -subj /CN=other.example.com 2>/dev/null && openssl x509 -req -in \(q(csr)) -CA \(q(ca)) -CAkey \(q(caKey)) -CAcreateserial -CAserial \(q(tmp.path + "/s.srl")) -days 30 -extfile \(q(ext)) -out \(q(crt)) 2>/dev/null")
		XCTAssertEqual(r.status, 0, r.err)
		LocalTLSIdentity.anchorCertificateOverride = URL(fileURLWithPath: ca)
		let rep = inspect(crt, key, host: "other.example.com").report
		XCTAssertEqual(rep.structural?.passed, false)
		print("NAME_CONSTRAINT structural code=\(rep.structural?.code ?? 0)")
	}
}

final class ManifestTests: XCTestCase {
	let pkg = URL(string: "https://ksign.backloop.dev:4431/a.ipa")!
	let img = URL(string: "https://ksign.backloop.dev:4431/app57x57.png")!

	func make(id: String? = "com.example.app", version: String? = "2.0", pkg: URL? = nil) throws -> Data {
		try LocalInstallerManifest.make(bundleIdentifier: id, bundleVersion: version, title: "App", packageURL: pkg ?? self.pkg, displayImageURL: img)
	}

	func testRoundTripAndValidate() throws {
		let v = LocalInstallerManifest.validate(try make(), expectedHost: "ksign.backloop.dev", expectedPort: 4431)
		XCTAssertTrue(v.isValid, "\(v.errors)")
		XCTAssertEqual(v.bundleIdentifier, "com.example.app")
		XCTAssertEqual(v.packageURL, pkg)
	}

	func testValidationFailures() throws {
		let data = try make()
		XCTAssertFalse(LocalInstallerManifest.validate(data, expectedHost: "ksign.backloop.dev", expectedPort: 5000).isValid)
		XCTAssertFalse(LocalInstallerManifest.validate(data, expectedHost: "other.example.com", expectedPort: 4431).isValid)
		let http = try make(pkg: URL(string: "http://ksign.backloop.dev:4431/a.ipa")!)
		XCTAssertTrue(LocalInstallerManifest.validate(http, expectedHost: "ksign.backloop.dev", expectedPort: 4431).errors.contains { $0.contains("https") })
		let wild = try make(pkg: URL(string: "https://*.backloop.dev:4431/a.ipa")!)
		XCTAssertFalse(LocalInstallerManifest.validate(wild, expectedHost: "*.backloop.dev", expectedPort: 4431).isValid)
		XCTAssertFalse(LocalInstallerManifest.validate(Data("nope".utf8), expectedHost: "x", expectedPort: 1).isValid)
	}

	func testMissingBundleIdentifierThrows() {
		XCTAssertThrowsError(try make(id: nil))
		XCTAssertThrowsError(try make(id: ""))
	}

	func testEmptyVersionDefaultsAndPlutilLint() throws {
		let data = try make(version: "")
		let root = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
		let meta = ((root?["items"] as? [[String: Any]])?.first?["metadata"]) as? [String: Any]
		XCTAssertEqual(meta?["bundle-version"] as? String, "1.0")
		let f = FileManager.default.temporaryDirectory.appendingPathComponent("m-\(UUID().uuidString).plist")
		defer { try? FileManager.default.removeItem(at: f) }
		try data.write(to: f)
		XCTAssertEqual(sh("plutil -lint \(q(f.path))").status, 0)
	}
}

final class RedactorTests: XCTestCase {
	func testSecretsAreRedacted() {
		for s in ["00008110-001A2B3C4D5E6F70", "0123456789abcdef0123456789abcdef01234567", "/Users/alice/Library/x", "password=abc123"] {
			let out = Redactor.clean("value \(s) end")
			XCTAssertTrue(out.contains("<redacted>"), out)
			XCTAssertFalse(out.contains("abc123"), out)
			XCTAssertFalse(out.contains("001A2B3C4D5E6F70"), out)
			XCTAssertFalse(out.contains("alice"), out)
		}
		let pem = "x\n-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\nAAAA\n-----END PRIVATE KEY-----\ny"
		let out = Redactor.clean(pem)
		XCTAssertFalse(out.contains("MIGHAgEA"), out)
		XCTAssertTrue(out.contains("<redacted>"))
	}

	func testLimitAndHarmlessText() {
		XCTAssertEqual(Redactor.clean(String(repeating: "a", count: 1000), limit: 50).count, 51)
		let plain = "TLS handshake: host=ksign.backloop.dev port=4431 code=-67901 fp=A6:EE:0D:5E sha=deadbeef"
		XCTAssertEqual(Redactor.clean(plain), plain)
	}
}
