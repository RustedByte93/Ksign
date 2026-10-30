//
//  LocalInstallerDiagnostics.swift
//  Ksign
//
//  Bounded, thread-safe structured event log plus the observable state behind
//  Settings > Installation > Local Installer Diagnostics.
//
//  Nothing in here may ever hold or export private keys, signing passwords, UDIDs or provisioning data.
//  Every free-text field goes through `Redactor`.
//

import Foundation
import SwiftUI
import Vapor

// MARK: - Event model

struct DiagnosticEvent: Codable, Identifiable {
	enum Level: String, Codable { case info, warning, error }

	var id = UUID()
	var timestamp = Date()
	var component: String
	var operationID: String
	var level: Level
	var event: String
	var message: String
	var pipelineState: String
	var hostname: String?
	var port: Int?
	var errorDomain: String?
	var errorCode: Int?
	var underlyingError: String?
	var failureReason: String?
	var metadata: [String: String] = [:]
}

/// Fixed-capacity ring buffer guarded by a lock. Safe to call from NIO event loops, URLSession
/// delegate queues and the main thread.
final class DiagnosticEventLog: @unchecked Sendable {
	static let shared = DiagnosticEventLog()
	static let capacity = 500

	private let lock = NSLock()
	private var events: [DiagnosticEvent] = []

	func append(_ event: DiagnosticEvent) {
		lock.lock(); defer { lock.unlock() }
		events.append(event)
		if events.count > Self.capacity { events.removeFirst(events.count - Self.capacity) }
	}

	var snapshot: [DiagnosticEvent] {
		lock.lock(); defer { lock.unlock() }
		return events
	}

	func clear() {
		lock.lock(); defer { lock.unlock() }
		events.removeAll()
	}
}

/// Receives swift-log output from NIO/Vapor and keeps only TLS-related lines (best effort: this is the only
/// window into server-side handshake failures, which NIO does not surface as events).
struct DiagnosticsLogHandler: LogHandler {
	var metadata: Logger.Metadata = [:]
	var logLevel: Logger.Level = .debug
	let label: String

	subscript(metadataKey key: String) -> Logger.Metadata.Value? {
		get { metadata[key] }
		set { metadata[key] = newValue }
	}

	func log(level: Logger.Level, message: Logger.Message, metadata: Logger.Metadata?, source: String, file: String, function: String, line: UInt) {
		let text = message.description
		guard text.range(of: "ssl|tls|handshake|certificate", options: [.regularExpression, .caseInsensitive]) != nil else { return }
		LocalInstallerDiagnostics.shared.log(
			component: "server.tls",
			event: "server.tls.logger",
			message: "(server logger, \(label)) \(text)",
			level: level >= .warning ? .warning : .info
		)
	}
}

// MARK: - Observable state

final class LocalInstallerDiagnostics: ObservableObject {
	static let shared = LocalInstallerDiagnostics()

	// Server state
	@Published var serverRunning = false
	@Published var boundAddress: String = "-"
	@Published var boundPort: Int?
	@Published var scheme: String = "-"
	@Published var hostname: String = "-"
	@Published var pipelineState: String = "idle"

	// Events
	@Published var lastError: String?
	@Published var lastManifestRequest: Date?
	@Published var lastManifestClient: String?
	@Published var lastIPARequest: Date?
	@Published var lastIPARange: String?
	@Published var lastIPAResult: String?
	@Published private(set) var recentEvents: [DiagnosticEvent] = []

	// Self test
	@Published var selfTestRunning = false
	@Published var runningTestName: String?
	@Published var stages: [StageResult] = []
	@Published var lastRun: Date?
	@Published var lastRunScope: String?

	private let stateLock = NSLock()
	private var stateName = "idle"
	private var stateHost: String?
	private var statePort: Int?

	var installMethodDescription: String {
		let installation = UserDefaults.standard.integer(forKey: "Feather.installationMethod")
		if installation == 1 { return "idevice (no local HTTPS server used)" }
		return ServerInstaller.getServerMethod() == 1
			? "Server – Semi Local (HTTP + external HTTPS manifest proxy)"
			: "Server – Fully Local (HTTPS, \(LocalTLSIdentity.resolveHostname()))"
	}

	// MARK: Structured logging (thread-safe)

	func setPipeline(_ state: String, hostname: String? = nil, port: Int? = nil) {
		stateLock.lock()
		stateName = state
		if let hostname { stateHost = hostname }
		if let port { statePort = port }
		stateLock.unlock()
		DispatchQueue.main.async { self.pipelineState = state }
	}

	func log(
		component: String,
		event: String,
		message: String,
		level: DiagnosticEvent.Level = .info,
		operation: String = "-",
		error: Error? = nil,
		hostname: String? = nil,
		port: Int? = nil,
		metadata: [String: String] = [:]
	) {
		stateLock.lock()
		let state = stateName, host = hostname ?? stateHost, p = port ?? statePort
		stateLock.unlock()

		var e = DiagnosticEvent(
			component: component,
			operationID: operation,
			level: error != nil && level == .info ? .error : level,
			event: event,
			message: Redactor.clean(message),
			pipelineState: state,
			hostname: host,
			port: p,
			metadata: metadata.mapValues { Redactor.clean($0, limit: 200) }
		)
		if let error {
			let ns = error as NSError
			e.errorDomain = ns.domain
			e.errorCode = ns.code
			e.failureReason = ns.localizedFailureReason.map { Redactor.clean($0) } ?? Redactor.clean(error.localizedDescription)
			if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
				e.underlyingError = Redactor.clean("\(underlying.domain) \(underlying.code): \(underlying.localizedDescription)")
			}
		}
		DiagnosticEventLog.shared.append(e)
		DispatchQueue.main.async { self.recentEvents = Array(DiagnosticEventLog.shared.snapshot.suffix(100)) }
	}

	// MARK: Recording used by the installer

	func serverStarted(address: String, port: Int, scheme: String, hostname: String, operation: String = "-") {
		setPipeline("listening", hostname: hostname, port: port)
		log(component: "server", event: "server.listener.started", message: "listening on \(address):\(port) (\(scheme))", operation: operation, hostname: hostname, port: port)
		DispatchQueue.main.async {
			self.serverRunning = true
			self.boundAddress = address
			self.boundPort = port
			self.scheme = scheme
			self.hostname = hostname
		}
	}

	func serverStopped(operation: String = "-", reason: String = "stopped") {
		setPipeline("stopped")
		log(component: "server", event: "server.stopped", message: reason, operation: operation)
		DispatchQueue.main.async { self.serverRunning = false }
	}

	func record(error: String, operation: String = "-", underlying: Error? = nil) {
		setPipeline("failed")
		log(component: "installer", event: "error", message: error, level: .error, operation: operation, error: underlying)
		DispatchQueue.main.async { self.lastError = Redactor.clean(error) }
	}

	func manifestRequested(client: String?, operation: String = "-") {
		setPipeline("manifest")
		log(component: "http", event: "http.manifest.requested", message: "manifest requested", operation: operation, metadata: ["client": client ?? "-"])
		DispatchQueue.main.async {
			self.lastManifestRequest = Date()
			self.lastManifestClient = client.map { Redactor.clean($0, limit: 120) }
		}
	}

	func ipaRequested(range: String?, operation: String = "-") {
		setPipeline("ipa-transfer")
		log(component: "http", event: "http.ipa.requested", message: "IPA requested", operation: operation, metadata: ["range": range ?? "-"])
		DispatchQueue.main.async {
			self.lastIPARequest = Date()
			self.lastIPARange = range
			self.lastIPAResult = "in progress"
		}
	}

	func ipaFinished(_ result: String, operation: String = "-") {
		DispatchQueue.main.async { self.lastIPAResult = result }
	}

	func clearEvents() {
		DiagnosticEventLog.shared.clear()
		DispatchQueue.main.async { self.recentEvents = [] }
	}
}
