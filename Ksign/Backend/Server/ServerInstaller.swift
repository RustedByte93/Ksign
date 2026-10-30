//
//  Server.swift
//  feather
//
//  Created by samara on 22.08.2024.
//  Copyright © 2024 Lakr Aream. All Rights Reserved.
//  ORIGINALLY LICENSED UNDER GPL-3.0, MODIFIED FOR USE FOR FEATHER
//

import Foundation
import Vapor
import NIOSSL
import NIOTLS
import SwiftUI
import IDeviceSwift

// MARK: - Class
class ServerInstaller: Identifiable, ObservableObject {
	/// Preferred port for the fully local HTTPS server. Falls back to a random port if it is busy.
	static let preferredPort = 4431

	let id = UUID()
	let operationID = "I-" + UUID().uuidString.prefix(8)
	private(set) var port: Int = ServerInstaller.preferredPort
	private var _needsShutdown = false
	private var _backgroundTask: UIBackgroundTaskIdentifier = .invalid
	private var _foregroundObserver: NSObjectProtocol?

	var packageUrl: URL?
	var app: AppInfoPresentable
	@ObservedObject var viewModel: InstallerStatusViewModel
	private var _server: Application?

	/// Non-nil when the server could not be started (missing/invalid certificate, port in use, ...).
	/// The UI must surface this instead of waiting on "Ready" forever.
	private(set) var startupError: Error?

	/// True once the itms-services URL was opened (after the trust check passed).
	var didRequestHandoff = false

	/// Never throws: a startup failure is recorded in `startupError` and `LocalInstallerDiagnostics`
	/// so the caller can show it (the previous `try!` call sites would crash the app).
	init(app: AppInfoPresentable, viewModel: InstallerStatusViewModel) {
		self.app = app
		self.viewModel = viewModel
		_start()

		_foregroundObserver = NotificationCenter.default.addObserver(
			forName: UIApplication.willEnterForegroundNotification,
			object: nil,
			queue: .main
		) { [weak self] _ in
			self?._restartIfNeeded()
		}
	}

	deinit {
		if let _foregroundObserver {
			NotificationCenter.default.removeObserver(_foregroundObserver)
		}
		_shutdownServer()
	}

	// MARK: Start / stop

	private func _start() {
		let diag = LocalInstallerDiagnostics.shared
		let hostname = Self.sni
		diag.setPipeline("server-init", hostname: hostname, port: Self.preferredPort)
		diag.log(component: "server", event: "server.init", message: "method=\(Self.getServerMethod() == 1 ? "semi-local" : "fully-local") bind=\(Self.bindAddress)", operation: operationID, hostname: hostname)

		if Self.getServerMethod() != 1 {
			if let identity = LocalTLSIdentity.inspectCurrent() {
				let r = identity.report
				diag.log(
					component: "tls", event: "tls.identity.selected",
					message: "source=\(identity.source.rawValue) usable=\(r.isUsable) keyMatches=\(r.keyMatches) hostnameInSAN=\(r.hostnameInSAN)",
					level: r.isUsable ? .info : .error, operation: operationID, hostname: hostname,
					metadata: [
						"sha256": r.fingerprint, "subject": r.subject, "issuer": r.issuer, "san": r.subjectAltNames.joined(separator: ","),
						"validityDays": r.validityDays.map(String.init) ?? "-",
						"structural": r.structural.map { $0.passed ? "passed" : "failed \($0.domain ?? "-") \($0.code.map(String.init) ?? "-")" } ?? "-",
					]
				)
			}
		}

		let candidates = [Self.preferredPort] + (0..<5).map { _ in Int.random(in: 4000...8000) }
		var lastError: Error?

		for (index, candidate) in candidates.enumerated() {
			var candidateApp: Application?
			diag.setPipeline("binding", hostname: hostname, port: candidate)
			diag.log(component: "server", event: "server.bind.attempt", message: "binding \(Self.bindAddress):\(candidate) (attempt \(index + 1) of \(candidates.count)\(index == 0 ? ", preferred port" : ", fallback"))", operation: operationID, hostname: hostname, port: candidate)
			do {
				let server = try Self.setupApp(port: candidate)
				candidateApp = server
				port = candidate
				_server = server
				try _configureRoutes(on: server)
				try server.server.start()
				_needsShutdown = true
				startupError = nil

				let scheme = Self.getServerMethod() == 1 ? "http" : "https"
				diag.serverStarted(address: Self.bindAddress, port: candidate, scheme: scheme, hostname: hostname, operation: operationID)
				diag.log(component: "server", event: "server.ipv.status", message: "IPv4 \(Self.bindAddress) bound; IPv6 not bound (by design)", operation: operationID, hostname: hostname, port: candidate)
				_beginBackgroundGrace()
				return
			} catch {
				lastError = error
				diag.log(component: "server", event: "server.listener.failed", message: "listener failed on port \(candidate)", level: .error, operation: operationID, error: error, hostname: hostname, port: candidate)
				candidateApp?.server.shutdown()
				candidateApp?.shutdown()
				_server = nil
				// A TLS problem will not be fixed by another port.
				if error is LocalTLSIdentity.IdentityError { break }
			}
		}

		startupError = lastError
		diag.serverStopped(operation: operationID, reason: "failed to start")
		if let lastError {
			diag.record(error: "Server failed to start: \(lastError.localizedDescription)", operation: operationID, underlying: lastError)
		}
	}

	private var _wasInterrupted = false

	/// Restarts the server only if iOS interrupted it while the app was in the background.
	private func _restartIfNeeded() {
		guard _wasInterrupted, !_needsShutdown else { return }
		_wasInterrupted = false
		_start()
	}

	// MARK: Routes

	private func _configureRoutes(on server: Application) throws {
		let op = operationID
		let diag = LocalInstallerDiagnostics.shared

		server.get("*") { [weak self] req in
			guard let self else { return Response(status: .badGateway) }
			switch req.url.path {
			case plistEndpoint.path:
				diag.manifestRequested(client: req.headers.first(name: .userAgent), operation: op)
				self._updateStatus(.sendingManifest)
				do {
					let data = try self.installManifestResult()
					diag.log(component: "http", event: "http.manifest.generated", message: "manifest generated (\(data.count) bytes)", operation: op, metadata: ["packageURL": self.payloadEndpoint.absoluteString])
					diag.log(component: "http", event: "http.manifest.delivered", message: "manifest response sent", operation: op)
					return Response(status: .ok, version: req.version, headers: [
						"Content-Type": "text/xml",
						"Cache-Control": "no-store",
					], body: .init(data: data))
				} catch {
					diag.record(error: "Manifest could not be generated: \(error.localizedDescription)", operation: op, underlying: error)
					return Response(status: .internalServerError)
				}
			case displayImageSmallEndpoint.path:
				return Response(status: .ok, version: req.version, headers: [
					"Content-Type": "image/png",
				], body: .init(data: displayImageSmallData))
			case displayImageLargeEndpoint.path:
				return Response(status: .ok, version: req.version, headers: [
					"Content-Type": "image/png",
				], body: .init(data: displayImageLargeData))
			case payloadEndpoint.path:
				guard let packageUrl = packageUrl else {
					diag.record(error: "IPA requested before it was ready", operation: op)
					return Response(status: .notFound)
				}

				var observer = IPAResponder.Observer()
				observer.started = { [weak self] range, offset, length, total in
					diag.ipaRequested(range: range, operation: op)
					diag.log(component: "http", event: range == nil ? "http.ipa.stream.started" : "http.ipa.range.stream.started",
							 message: "streaming \(length) of \(total) bytes from offset \(offset)", operation: op,
							 metadata: ["range": range ?? "-", "offset": "\(offset)", "length": "\(length)", "total": "\(total)"])
					self?._updateStatus(.sendingPayload)
				}
				observer.finished = { [weak self] outcome, expected in
					switch outcome {
					case .completed(let bytes):
						diag.ipaFinished("sent \(bytes) bytes", operation: op)
						diag.log(component: "http", event: "http.ipa.stream.completed", message: "transferred \(bytes) of \(expected) bytes", operation: op, metadata: ["bytes": "\(bytes)"])
						// "installing" = payload delivered; whether iOS installs it is only known to iOS.
						self?._updateStatus(.installing)
					case .interrupted(let bytes, let error):
						diag.ipaFinished("interrupted after \(bytes) of \(expected) bytes: \(error.localizedDescription)", operation: op)
						diag.log(component: "http", event: "http.ipa.stream.interrupted", message: "interrupted after \(bytes) of \(expected) bytes", level: .warning, operation: op, error: error, metadata: ["bytes": "\(bytes)"])
						// A client that drops a connection and re-requests with Range is normal for installd;
						// only surface it as broken if no later request completes.
					}
				}
				return IPAResponder.response(for: req, fileURL: packageUrl, observer: observer)
			case "/install":
				var headers = HTTPHeaders()
				headers.add(name: .contentType, value: "text/html; charset=utf-8")
				return Response(status: .ok, headers: headers, body: .init(string: self.html))
			case "/health":
				diag.log(component: "http", event: "http.health.requested", message: "health request received", operation: op)
				return Response(status: .ok, body: .init(string: "ok"))
			default:
				return Response(status: .notFound)
			}
		}
	}

	// MARK: Lifecycle

	/// Asks iOS for extra background time so a transfer that has begun is not killed instantly when
	/// the user switches to the system install prompt. If time runs out the server is shut down
	/// cleanly and the failure is surfaced rather than leaving the UI stuck.
	private func _beginBackgroundGrace() {
		DispatchQueue.main.async { [weak self] in
			guard let self, self._backgroundTask == .invalid else { return }
			self._backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "KsignLocalInstaller") { [weak self] in
				self?._handleBackgroundExpiration()
			}
		}
	}

	private func _endBackgroundGrace() {
		DispatchQueue.main.async { [weak self] in
			guard let self, self._backgroundTask != .invalid else { return }
			UIApplication.shared.endBackgroundTask(self._backgroundTask)
			self._backgroundTask = .invalid
		}
	}

	private func _handleBackgroundExpiration() {
		LocalInstallerDiagnostics.shared.log(component: "lifecycle", event: "background.expired", message: "iOS background time expired; stopping local server", level: .warning, operation: operationID)
		_wasInterrupted = true
		if case .installing = viewModel.status {
			// payload already delivered; installd continues without us
		} else if case .completed = viewModel.status {
		} else {
			LocalInstallerDiagnostics.shared.record(error: "iOS suspended Ksign before the install finished; the local server was stopped. Re-open Ksign to retry.", operation: operationID)
		}
		_shutdownServer()
		_endBackgroundGrace()
	}

	private func _shutdownServer() {
		guard _needsShutdown else { return }

		_needsShutdown = false
		LocalInstallerDiagnostics.shared.serverStopped(operation: operationID)
		_server?.server.shutdown()
		_server?.shutdown()
		_server = nil
		_endBackgroundGrace()
	}

	private func _updateStatus(_ newStatus: InstallerStatusViewModel.InstallerStatus) {
		DispatchQueue.main.async {
			self.viewModel.status = newStatus
		}
	}

	// MARK: Settings

	/// 0 = Fully Local (HTTPS with the local TLS identity), 1 = Semi Local (HTTP + external HTTPS manifest proxy).
	/// Defaults to Fully Local when the user never chose, matching the UI default.
	static func getServerMethod() -> Int {
		UserDefaults.standard.object(forKey: "Feather.serverMethod") as? Int ?? 0
	}

	static func getIPFix() -> Bool {
		UserDefaults.standard.bool(forKey: "Feather.ipFix")
	}

	static func setServerMethod(_ method: Int) {
		UserDefaults.standard.set(method, forKey: "Feather.serverMethod")
	}

	static func setIPFix(_ enabled: Bool) {
		UserDefaults.standard.set(enabled, forKey: "Feather.ipFix")
	}
}

// MARK: - OTA hand-off

extension ServerInstaller {
	/// Opens the itms-services URL only after a strict HTTPS request to THIS server succeeded with the
	/// normal system trust policy. Untrusted endpoints are never handed to iOS and verification is never
	/// bypassed. Opening the URL is a hand-off, not an installation: no success is recorded here.
	@MainActor
	func handOffToiOS(onRefused: @escaping (String) -> Void) {
		let diag = LocalInstallerDiagnostics.shared
		let host = Self.sni, port = self.port, op = operationID
		diag.setPipeline("trust-check", hostname: host, port: port)
		Task {
			if let failure = await LocalInstallerSelfTest.verifyInstallerTrust(host: host, port: port, operation: op) {
				diag.record(error: "Install refused: \(failure)", operation: op)
				onRefused(failure + "\n\nSee Settings > Installation > Local Installer Diagnostics.")
				return
			}
			diag.setPipeline("handoff")
			diag.log(component: "ota", event: "ota.handoff.requested", message: "opening itms-services URL; the OS installation outcome is not observable from Ksign", operation: op, hostname: host, port: port,
					 metadata: ["manifest": plistEndpoint.absoluteString])
			didRequestHandoff = true
			_ = await UIApplication.shared.open(URL(string: iTunesLink)!)
		}
	}
}
