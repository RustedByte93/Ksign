import Foundation
import Vapor
import NIOSSL
@testable import LocalInstallerCore

// MARK: - Shell

struct ShellResult { let status: Int32; let out: String; let err: String }

@discardableResult
func sh(_ command: String) -> ShellResult {
	let p = Process()
	p.executableURL = URL(fileURLWithPath: "/bin/sh")
	p.arguments = ["-c", command]
	let o = Pipe(), e = Pipe()
	p.standardOutput = o; p.standardError = e
	try! p.run()
	let outData = o.fileHandleForReading.readDataToEndOfFile()
	let errData = e.fileHandleForReading.readDataToEndOfFile()
	p.waitUntilExit()
	for h in [o.fileHandleForReading, o.fileHandleForWriting, e.fileHandleForReading, e.fileHandleForWriting] { try? h.close() }
	return ShellResult(
		status: p.terminationStatus,
		out: String(decoding: outData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
		err: String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
	)
}

func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

func sha256(file: String) -> String { sh("shasum -a 256 \(q(file)) | cut -d' ' -f1").out }

/// SHA-256 of bytes [offset, offset+length) of a file.
func sha256(file: String, offset: Int64, length: Int64) -> String {
	sh("tail -c +\(offset + 1) \(q(file)) | head -c \(length) | shasum -a 256 | cut -d' ' -f1").out
}

func repoRoot(_ file: StaticString = #filePath) -> URL {
	var url = URL(fileURLWithPath: "\(file)")
	for _ in 0..<5 { url.deleteLastPathComponent() }
	return url
}

// MARK: - Fixtures

enum Fixtures {
	static let dir: URL = {
		let d = FileManager.default.temporaryDirectory.appendingPathComponent("ksign-localinstaller-tests-\(ProcessInfo.processInfo.processIdentifier)")
		try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
		atexit { try? FileManager.default.removeItem(at: Fixtures.dir) }
		return d
	}()

	/// Small random file with an awkward (non block-aligned) size.
	static let small: URL = {
		let url = dir.appendingPathComponent("small.ipa")
		_ = sh("head -c 5242999 /dev/urandom > \(q(url.path))")
		return url
	}()

	private static var cache: [Int: URL] = [:]
	private static let lock = NSLock()

	/// `megabytes` MiB made of 1 MiB blocks: one random block, stamped with the block counter in its first 8 bytes,
	/// so every offset has distinct, verifiable content but generation is cheap.
	static func large(megabytes: Int) -> URL {
		lock.lock(); defer { lock.unlock() }
		if let url = cache[megabytes] { return url }
		let url = dir.appendingPathComponent("large-\(megabytes).ipa")
		FileManager.default.createFile(atPath: url.path, contents: nil)
		let handle = try! FileHandle(forWritingTo: url)
		var base = [UInt8](repeating: 0, count: 1 << 20)
		var gen = SystemRandomNumberGenerator()
		base.withUnsafeMutableBytes { raw in
			let words = raw.bindMemory(to: UInt64.self)
			for i in 0..<words.count { words[i] = gen.next() }
		}
		for block in 0..<megabytes {
			var counter = UInt64(block).bigEndian
			withUnsafeBytes(of: &counter) { for i in 0..<8 { base[i] = $0[i] } }
			handle.write(Data(base))
		}
		try! handle.close()
		cache[megabytes] = url
		return url
	}
}

// MARK: - Observer recorder

final class Recorder: @unchecked Sendable {
	struct Start { let range: String?; let offset: Int64; let length: Int64; let total: Int64 }
	private let lock = NSLock()
	private var _starts: [Start] = []
	private var _outcomes: [(IPAResponder.Outcome, Int64)] = []

	var starts: [Start] { lock.lock(); defer { lock.unlock() }; return _starts }
	var outcomes: [(IPAResponder.Outcome, Int64)] { lock.lock(); defer { lock.unlock() }; return _outcomes }

	func observer() -> IPAResponder.Observer {
		var o = IPAResponder.Observer()
		o.started = { [self] r, off, len, total in lock.lock(); _starts.append(.init(range: r, offset: off, length: len, total: total)); lock.unlock() }
		o.finished = { [self] outcome, expected in lock.lock(); _outcomes.append((outcome, expected)); lock.unlock() }
		return o
	}

	func waitForOutcomes(_ n: Int, timeout: TimeInterval = 15) -> Bool {
		let deadline = Date().addingTimeInterval(timeout)
		while Date() < deadline {
			if outcomes.count >= n { return true }
			Thread.sleep(forTimeInterval: 0.05)
		}
		return outcomes.count >= n
	}
}

// MARK: - Server

final class TestServer {
	let app: Application
	let port: Int
	let recorder = Recorder()

	/// `files` maps the URL name (`/file/<name>`) to a file on disk.
	init(files: [String: URL], tls: (crt: String, key: String)? = nil) throws {
		let app = Application(.testing)
		app.logger.logLevel = .warning
		app.http.server.configuration.hostname = "127.0.0.1"
		app.http.server.configuration.port = 0
		if let tls {
			var config = try TLSConfiguration.makeServerConfiguration(
				certificateChain: try NIOSSLCertificate.fromPEMFile(tls.crt).map { .certificate($0) },
				privateKey: .privateKey(try NIOSSLPrivateKey(file: tls.key, format: .pem))
			)
			config.minimumTLSVersion = .tlsv12
			app.http.server.configuration.tlsConfiguration = config
		}
		let recorder = self.recorder
		app.get("health") { _ in "ok" }
		app.get("file", ":name") { req -> Response in
			guard let name = req.parameters.get("name"), let url = files[name] else { return Response(status: .notFound) }
			return IPAResponder.response(for: req, fileURL: url, observer: recorder.observer())
		}
		try app.server.start()
		guard let port = app.http.server.shared.localAddress?.port else {
			app.shutdown()
			throw Abort(.internalServerError, reason: "server has no bound port")
		}
		self.app = app
		self.port = port
	}

	var http: String { "http://127.0.0.1:\(port)" }

	func shutdown() {
		app.server.shutdown()
		app.shutdown()
	}
}

// MARK: - Process metrics

func residentKB() -> Int {
	Int(sh("ps -o rss= -p \(getpid())").out) ?? 0
}

func openFDCount() -> Int {
	(try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? -1
}

/// Runs `body` while sampling this process's RSS every 50 ms; returns (result, peak growth in MB).
func withRSSSampling<T>(_ body: () -> T) -> (T, Double) {
	let baseline = residentKB()
	let state = SamplerState(peak: baseline)
	let thread = Thread {
		while !state.stop {
			state.record(residentKB())
			Thread.sleep(forTimeInterval: 0.05)
		}
	}
	thread.start()
	let result = body()
	state.stop = true
	Thread.sleep(forTimeInterval: 0.1)
	return (result, Double(max(0, state.peak - baseline)) / 1024.0)
}

private final class SamplerState: @unchecked Sendable {
	private let lock = NSLock()
	private var _peak: Int
	private var _stop = false
	init(peak: Int) { _peak = peak }
	var peak: Int { lock.lock(); defer { lock.unlock() }; return _peak }
	var stop: Bool {
		get { lock.lock(); defer { lock.unlock() }; return _stop }
		set { lock.lock(); _stop = newValue; lock.unlock() }
	}
	func record(_ v: Int) { lock.lock(); _peak = max(_peak, v); lock.unlock() }
}

// MARK: - PKI

struct PKI {
	let dir: URL
	var crt: String { dir.appendingPathComponent("out/server.crt").path }
	var key: String { dir.appendingPathComponent("out/server.pem").path }
	var ca: String { dir.appendingPathComponent("out/KsignLocalCA.crt").path }

	static func generate() throws -> PKI {
		let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ksign-pki-tests-\(UUID().uuidString)")
		try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
		let script = repoRoot().appendingPathComponent("Scripts/make-local-pki.sh").path
		let r = sh("sh \(q(script)) --out \(q(dir.path + "/out")) --pki-dir \(q(dir.path + "/pki"))")
		guard r.status == 0 else { throw Abort(.internalServerError, reason: "PKI script failed: \(r.err) \(r.out)") }
		return PKI(dir: dir)
	}
}

func lsofSnapshot() -> [String] {
	sh("lsof -p \(getpid()) -nP 2>/dev/null | awk 'NR>1 {print $4, $5, $9}'").out.split(separator: "\n").map(String.init)
}
