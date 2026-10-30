//
//  LocalInstallerDiagnosticsView.swift
//  Ksign
//
//  "Local Installer Diagnostics": staged self-test, certificate details, trust profile and exportable report.
//

import SwiftUI
import NimbleViews

struct LocalInstallerDiagnosticsView: View {
	@StateObject private var diag = LocalInstallerDiagnostics.shared
	@State private var identity: LocalTLSIdentity?
	@State private var bundleURL: URL?
	@State private var exportError: String?
	@State private var copied = false

	private static let dateFormatter: DateFormatter = {
		let f = DateFormatter()
		f.dateStyle = .medium
		f.timeStyle = .medium
		return f
	}()

	private static let timeFormatter: DateFormatter = {
		let f = DateFormatter()
		f.dateFormat = "HH:mm:ss.SSS"
		return f
	}()

	var body: some View {
		NBList("Local Installer Diagnostics") {
			resultsSection
			actionsSection
			certificateSection
			trustSection
			serverSection
			eventsSection
			exportSection
		}
		.onAppear { identity = LocalTLSIdentity.inspectCurrent() }
	}

	// MARK: Sections

	private var resultsSection: some View {
		Section {
			if diag.stages.isEmpty {
				Text("No test has been run yet.").foregroundStyle(.secondary)
			}
			ForEach(diag.stages) { stage in
				VStack(alignment: .leading, spacing: 3) {
					HStack {
						Text(stage.id.title).font(.subheadline.weight(.semibold))
						Spacer()
						Text(stage.status.rawValue).font(.caption.weight(.bold)).foregroundStyle(color(stage.status))
					}
					Text(stage.detail).font(.footnote).foregroundStyle(.secondary).textSelection(.enabled)
					if let code = stage.errorCode {
						Text("\(stage.errorDomain ?? "error") \(code)").font(.system(.caption, design: .monospaced)).foregroundStyle(.red)
					}
					if let next = stage.nextAction, stage.status != .pass {
						Label(next, systemImage: "arrow.turn.down.right").font(.footnote).foregroundStyle(.orange)
					}
				}
				.padding(.vertical, 2)
			}
		} header: {
			Text(diag.lastRun.map { "Self-test – \(Self.dateFormatter.string(from: $0)) (\(diag.lastRunScope ?? "-"))" } ?? "Self-test")
		} footer: {
			Text("NOT TESTED means a prerequisite failed or the step was not run; it is not a failure. PASS means this app completed a strictly validated HTTPS request to its own server – it does not prove iOS will install an app.")
		}
	}

	private var actionsSection: some View {
		Section {
			testButton("Run Full Diagnostics", "stethoscope", .full)
			testButton("Test Certificate", "doc.badge.gearshape", .certificate)
			testButton("Test HTTPS Listener", "network", .listener)
			testButton("Test System TLS Trust", "lock.shield", .systemTrust)
			testButton("Test Manifest", "list.bullet.rectangle", .manifest)
			testButton("Test IPA Endpoint", "shippingbox", .ipa)
			if diag.selfTestRunning {
				HStack { ProgressView(); Text("Running: \(diag.runningTestName ?? "")").foregroundStyle(.secondary) }
			}
		} header: {
			Text("Tests")
		} footer: {
			Text("Each test starts a temporary diagnostic server on 127.0.0.1 and checks only what its name says; earlier stages it depends on are run silently. Normal certificate verification is never disabled.")
		}
	}

	@ViewBuilder
	private var certificateSection: some View {
		Section("TLS certificate") {
			if let identity {
				let r = identity.report
				row("Source", identity.source.rawValue)
				row("Subject", r.subject)
				row("Issuer", r.issuer + (r.isSelfSigned ? " (self-signed)" : ""))
				row("SAN", r.subjectAltNames.isEmpty ? "-" : r.subjectAltNames.joined(separator: ", "))
				row("Valid from", date(r.notBefore))
				row("Valid until", date(r.notAfter), bad: r.isExpired)
				row("Validity", "\(r.validityDays.map(String.init) ?? "?") days (Apple limit \(LocalTLSIdentity.appleMaximumValidityDays))", bad: (r.validityDays ?? 0) > LocalTLSIdentity.appleMaximumValidityDays)
				row("SHA-256", r.fingerprint, mono: true)
				row("Private key matches", yesNo(r.keyMatches), bad: !r.keyMatches)
				row("Covers \(identity.hostname)", yesNo(r.hostnameInSAN), bad: !r.hostnameInSAN)
				if let s = r.structural {
					row("Structure check", s.passed ? "passed" : "\(s.message) [\(s.domain ?? "-") \(s.code.map(String.init) ?? "-")]", bad: !s.passed)
				}
				if !r.problems.isEmpty { row("Problems", r.problems.joined(separator: "\n"), bad: true) }
				if !r.warnings.isEmpty { row("Warnings", r.warnings.joined(separator: "\n")) }
			} else {
				row("Certificate", "none found", bad: true)
			}
		}
	}

	@ViewBuilder
	private var trustSection: some View {
		Section {
			if let profile = LocalTLSIdentity.trustProfileURL() {
				ShareLink(item: profile) {
					Label("Export Trust Profile (KsignLocalCA.mobileconfig)", systemImage: "square.and.arrow.up")
				}
			} else {
				Text("This build has no private CA profile. Use a build made with Scripts/make-local-pki.sh, or supply your own certificate.")
					.foregroundStyle(.secondary)
			}
		} header: {
			Text("Device trust")
		} footer: {
			Text("Nothing is installed or trusted automatically. 1) Export the profile and save it to Files. 2) Open it from Files and install it in Settings ▸ General ▸ VPN & Device Management. 3) Enable it under Settings ▸ General ▸ About ▸ Certificate Trust Settings. The CA can only vouch for \(LocalTLSIdentity.resolveHostname()).")
		}
	}

	private var serverSection: some View {
		Section("Server") {
			row("Install method", diag.installMethodDescription)
			row("Pipeline state", diag.pipelineState)
			row("Running", yesNo(diag.serverRunning))
			row("Bound address", "\(diag.boundAddress):\(diag.boundPort.map(String.init) ?? "-")")
			row("Hostname", diag.hostname)
			row("Last manifest request", date(diag.lastManifestRequest, none: "never"))
			row("Last IPA download", date(diag.lastIPARequest, none: "never"))
			if let range = diag.lastIPARange { row("IPA range", range) }
			if let result = diag.lastIPAResult { row("IPA result", result) }
			row("Last error", diag.lastError ?? "none", bad: diag.lastError != nil)
		}
	}

	private var eventsSection: some View {
		Section {
			if diag.recentEvents.isEmpty { Text("No events yet.").foregroundStyle(.secondary) }
			ForEach(diag.recentEvents.reversed().prefix(40)) { e in
				VStack(alignment: .leading, spacing: 1) {
					Text("\(Self.timeFormatter.string(from: e.timestamp))  \(e.component)  \(e.event)")
						.font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
					Text(e.message).font(.footnote).foregroundStyle(e.level == .error ? Color.red : Color.primary)
					if let c = e.errorCode { Text("\(e.errorDomain ?? "-") \(c)").font(.system(.caption2, design: .monospaced)).foregroundStyle(.red) }
				}
			}
			if !diag.recentEvents.isEmpty {
				Button("Clear events", role: .destructive) { diag.clearEvents() }
			}
		} header: {
			Text("Events (newest first)")
		}
	}

	private var exportSection: some View {
		Section {
			Button {
				UIPasteboard.general.string = diag.textReport
				copied = true
			} label: {
				Label(copied ? "Copied" : "Copy Full Report", systemImage: "doc.on.doc")
			}

			Button {
				do { bundleURL = try diag.exportBundle(); exportError = nil } catch { exportError = error.localizedDescription }
			} label: {
				Label("Export Diagnostic Bundle", systemImage: "archivebox")
			}
			if let bundleURL {
				ShareLink(item: bundleURL) { Label("Share \(bundleURL.lastPathComponent)", systemImage: "square.and.arrow.up") }
			}
			if let exportError { Text(exportError).foregroundStyle(.red) }
		} footer: {
			Text("The bundle holds report.txt, report.json and events.json (and the public CA certificate). It never contains private keys, signing certificates or passwords, UDIDs or provisioning data.")
		}
	}

	// MARK: Helpers

	private func testButton(_ title: String, _ icon: String, _ scope: LocalInstallerSelfTest.Scope) -> some View {
		Button {
			copied = false
			Task { await diag.run(scope, name: title) }
		} label: {
			Label(title, systemImage: icon)
		}
		.disabled(diag.selfTestRunning)
	}

	private func color(_ status: StageStatus) -> Color {
		switch status {
		case .pass: return .green
		case .fail: return .red
		case .notTested: return .secondary
		}
	}

	private func row(_ title: String, _ value: String, mono: Bool = false, bad: Bool = false) -> some View {
		VStack(alignment: .leading, spacing: 2) {
			Text(title).font(.caption).foregroundStyle(.secondary)
			Text(value)
				.font(mono ? .system(.footnote, design: .monospaced) : .body)
				.foregroundStyle(bad ? Color.red : Color.primary)
				.textSelection(.enabled)
		}
	}

	private func yesNo(_ value: Bool) -> String { value ? "Yes" : "No" }

	private func date(_ d: Date?, none: String = "-") -> String {
		d.map { Self.dateFormatter.string(from: $0) } ?? none
	}
}
