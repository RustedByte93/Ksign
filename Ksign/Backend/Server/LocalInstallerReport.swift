//
//  LocalInstallerReport.swift
//  Ksign
//
//  Builds the exportable diagnostic report (human-readable text + structured JSON) and the export bundle.
//  Contains only public/safe metadata: certificate subject/SAN/dates/fingerprint, ports, error codes.
//  It never reads or includes the private key, signing certificates/passwords, UDIDs or provisioning data.
//

import Foundation
import UIKit
import ZIPFoundation

struct DiagnosticReport: Codable {
	struct Certificate: Codable {
		var source: String
		var sha256: String
		var subject: String
		var issuer: String
		var selfSigned: Bool
		var subjectAltNames: [String]
		var notBefore: Date?
		var notAfter: Date?
		var validityDays: Int?
		var expired: Bool
		var hostnameInSAN: Bool
		var privateKeyMatches: Bool
		var sharedPublicKey: Bool
		var structuralCheck: String
		var problems: [String]
		var warnings: [String]
	}

	var generated: Date
	var appVersion: String
	var systemVersion: String
	var deviceModel: String
	var installMethod: String
	var hostname: String
	var certificate: Certificate?
	var serverRunning: Bool
	var boundAddress: String
	var boundPort: Int?
	var pipelineState: String
	var lastManifestRequest: Date?
	var lastIPARequest: Date?
	var lastIPARange: String?
	var lastIPAResult: String?
	var lastError: String?
	var lastRun: Date?
	var lastRunScope: String?
	var stages: [StageResult]
	var events: [DiagnosticEvent]
	var notes: [String]
}

extension LocalInstallerDiagnostics {
	private static var deviceModelIdentifier: String {
		var info = utsname(); uname(&info)
		return withUnsafePointer(to: &info.machine) {
			$0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
		}
	}

	func makeReport() -> DiagnosticReport {
		var cert: DiagnosticReport.Certificate?
		if let id = LocalTLSIdentity.inspectCurrent() {
			let r = id.report
			cert = .init(
				source: id.source.rawValue, sha256: r.fingerprint, subject: r.subject, issuer: r.issuer, selfSigned: r.isSelfSigned,
				subjectAltNames: r.subjectAltNames, notBefore: r.notBefore, notAfter: r.notAfter, validityDays: r.validityDays,
				expired: r.isExpired, hostnameInSAN: r.hostnameInSAN, privateKeyMatches: r.keyMatches, sharedPublicKey: r.isSharedPublicKey,
				structuralCheck: r.structural.map { $0.passed ? "passed (\($0.anchorDescription))" : "failed: \($0.message) [\($0.domain ?? "-") \($0.code.map(String.init) ?? "-")]" } ?? "not run",
				problems: r.problems, warnings: r.warnings
			)
		}
		let info = Bundle.main.infoDictionary
		return DiagnosticReport(
			generated: Date(),
			appVersion: "\(info?["CFBundleShortVersionString"] as? String ?? "?") (\(info?["CFBundleVersion"] as? String ?? "?"))",
			systemVersion: UIDevice.current.systemVersion,
			deviceModel: Self.deviceModelIdentifier,
			installMethod: installMethodDescription,
			hostname: LocalTLSIdentity.resolveHostname(),
			certificate: cert,
			serverRunning: serverRunning, boundAddress: boundAddress, boundPort: boundPort, pipelineState: pipelineState,
			lastManifestRequest: lastManifestRequest, lastIPARequest: lastIPARequest, lastIPARange: lastIPARange,
			lastIPAResult: lastIPAResult, lastError: lastError, lastRun: lastRun, lastRunScope: lastRunScope,
			stages: StageID.allCases.map { id in stages.first { $0.id == id } ?? .notTested(id, "not run yet") },
			events: DiagnosticEventLog.shared.snapshot,
			notes: [
				"PASS means this app completed a strictly validated HTTPS request to its own server. It does not prove iOS can install an app.",
				"NOT TESTED means a prerequisite failed or the test was not run; it is not a failure.",
				"Private keys, signing credentials, UDIDs and provisioning data are never included.",
			]
		)
	}

	var textReport: String {
		let r = makeReport()
		let df = DateFormatter(); df.dateStyle = .medium; df.timeStyle = .medium
		func d(_ date: Date?) -> String { date.map(df.string(from:)) ?? "never" }

		var lines = ["LOCAL INSTALLER SELF-TEST", ""]
		lines.append("Run: \(d(r.lastRun)) scope=\(r.lastRunScope ?? "-")")
		lines.append("")
		for s in r.stages {
			lines.append("\(s.id.title):")
			let detail = s.detail.replacingOccurrences(of: "\n", with: "\n    ")
			lines.append("\(s.status.rawValue) - \(detail)")
			if let code = s.errorCode { lines.append("    error: \(s.errorDomain ?? "-") \(code)") }
			if let next = s.nextAction, s.status != .pass { lines.append("    next: \(next)") }
			lines.append("")
		}

		lines.append("--- Environment ---")
		lines += [
			"Generated: \(d(r.generated))",
			"Ksign \(r.appVersion), iOS \(r.systemVersion), \(r.deviceModel)",
			"Install method: \(r.installMethod)",
			"Hostname: \(r.hostname)",
		]
		if let c = r.certificate {
			lines += [
				"Certificate source: \(c.source)",
				"SHA-256: \(c.sha256)",
				"Subject: \(c.subject)",
				"Issuer: \(c.issuer)\(c.selfSigned ? " (self-signed)" : "")",
				"SAN: \(c.subjectAltNames.joined(separator: ", "))",
				"Valid: \(d(c.notBefore)) → \(d(c.notAfter)) (\(c.validityDays.map(String.init) ?? "?") days), expired: \(c.expired)",
				"Private key matches: \(c.privateKeyMatches)",
				"Shared public key: \(c.sharedPublicKey)",
				"Structural check: \(c.structuralCheck)",
				"Problems: \(c.problems.isEmpty ? "none" : c.problems.joined(separator: "; "))",
				"Warnings: \(c.warnings.isEmpty ? "none" : c.warnings.joined(separator: "; "))",
			]
		} else {
			lines.append("Certificate: none found")
		}
		lines += [
			"Server running: \(r.serverRunning)",
			"Bound: \(r.boundAddress):\(r.boundPort.map(String.init) ?? "-")",
			"Pipeline state: \(r.pipelineState)",
			"Last manifest request: \(d(r.lastManifestRequest))",
			"Last IPA request: \(d(r.lastIPARequest)) range=\(r.lastIPARange ?? "-") result=\(r.lastIPAResult ?? "-")",
			"Last error: \(r.lastError ?? "none")",
			"",
			"--- Last \(min(r.events.count, 60)) events (of \(r.events.count)) ---",
		]
		let tf = DateFormatter(); tf.dateFormat = "HH:mm:ss.SSS"
		for e in r.events.suffix(60) {
			var line = "\(tf.string(from: e.timestamp)) [\(e.level.rawValue)] \(e.component) \(e.event) op=\(e.operationID) state=\(e.pipelineState)"
			if let h = e.hostname { line += " host=\(h)" }
			if let p = e.port { line += " port=\(p)" }
			line += " – \(e.message)"
			if let c = e.errorCode { line += " (\(e.errorDomain ?? "-") \(c)\(e.failureReason.map { ": \($0)" } ?? ""))" }
			lines.append(line)
		}
		lines += ["", r.notes.joined(separator: "\n")]
		return lines.joined(separator: "\n")
	}

	func jsonReport() throws -> Data {
		let encoder = JSONEncoder()
		encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
		encoder.dateEncodingStrategy = .iso8601
		return try encoder.encode(makeReport())
	}

	/// report.txt + report.json + events.json (+ the PUBLIC CA certificate if shipped) in one zip.
	func exportBundle() throws -> URL {
		let fm = FileManager.default
		let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
		let dir = fm.temporaryDirectory.appendingPathComponent("KsignDiagnostics-\(stamp)", isDirectory: true)
		try? fm.removeItem(at: dir)
		try fm.createDirectory(at: dir, withIntermediateDirectories: true)

		try textReport.write(to: dir.appendingPathComponent("report.txt"), atomically: true, encoding: .utf8)
		try jsonReport().write(to: dir.appendingPathComponent("report.json"))
		let encoder = JSONEncoder()
		encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
		encoder.dateEncodingStrategy = .iso8601
		try encoder.encode(DiagnosticEventLog.shared.snapshot).write(to: dir.appendingPathComponent("events.json"))
		if let ca = LocalTLSIdentity.anchorCertificateURL() {
			try? fm.copyItem(at: ca, to: dir.appendingPathComponent("KsignLocalCA.crt"))   // public certificate only
		}

		let zip = fm.temporaryDirectory.appendingPathComponent("KsignDiagnostics-\(stamp).zip")
		try? fm.removeItem(at: zip)
		try fm.zipItem(at: dir, to: zip, shouldKeepParent: true)
		try? fm.removeItem(at: dir)
		return zip
	}

	@MainActor
	func run(_ scope: LocalInstallerSelfTest.Scope, name: String) async {
		guard !selfTestRunning else { return }
		selfTestRunning = true
		runningTestName = name
		let results = await LocalInstallerSelfTest.run(scope: scope)
		// A partial run only replaces the stages it actually evaluated; "not part of this test" must not
		// overwrite an earlier real result.
		if scope == .full {
			stages = results
		} else {
			let evaluated = results.filter { !$0.detail.hasPrefix("not part of this test") }
			stages = StageID.allCases.compactMap { id in evaluated.first { $0.id == id } ?? stages.first { $0.id == id } }
		}
		lastRun = Date()
		lastRunScope = scope.rawValue
		if let firstFail = results.first(where: { $0.status == .fail }) {
			lastError = "\(firstFail.id.title): \(Redactor.clean(firstFail.detail))"
		}
		runningTestName = nil
		selfTestRunning = false
	}
}
