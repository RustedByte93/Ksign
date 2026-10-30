import XCTest
import Vapor
@testable import LocalInstallerCore

private let skipLarge = ProcessInfo.processInfo.environment["KSIGN_SKIP_LARGE"] == "1"

final class IPAResponderTests: XCTestCase {
	// MARK: selectRange

	func testSelectRangeTable() {
		let size: Int64 = 100
		typealias R = IPAResponder.RangeSelection
		let table: [(String?, R)] = [
			(nil, .whole),
			("bytes=0-0", .partial(offset: 0, length: 1)),
			("bytes=5-", .partial(offset: 5, length: 95)),
			("bytes=-10", .partial(offset: 90, length: 10)),
			("bytes=-1000", .partial(offset: 0, length: 100)),
			("bytes=90-1000", .partial(offset: 90, length: 10)),
			("bytes=0-99", .partial(offset: 0, length: 100)),
			("bytes=100-", .unsatisfiable),
			("bytes=100-200", .unsatisfiable),
			("bytes=500-", .unsatisfiable),
			("bytes=abc", .whole),
			("bytes=", .whole),
			("bytes=-", .whole),
			("bytes=5-2", .whole),
			("bytes=-0", .whole),
			("bytes=0-1,5-6", .whole),
			("items=0-5", .whole),
			("garbage", .whole),
			("BYTES=2-3", .partial(offset: 2, length: 2)),
		]
		for (header, expected) in table {
			XCTAssertEqual(IPAResponder.selectRange(header: header, size: size), expected, "header: \(header ?? "nil")")
		}
	}

	func testSelectRangeEmptyFile() {
		XCTAssertEqual(IPAResponder.selectRange(header: nil, size: 0), .whole)
		XCTAssertEqual(IPAResponder.selectRange(header: "bytes=0-", size: 0), .unsatisfiable)
		XCTAssertEqual(IPAResponder.selectRange(header: "bytes=-5", size: 0), .unsatisfiable)
	}

	// MARK: Plain HTTP

	func testFullResponseHeadersBodyAndAccounting() throws {
		let src = Fixtures.small
		let size = (try FileManager.default.attributesOfItem(atPath: src.path)[.size] as! NSNumber).int64Value
		let server = try TestServer(files: ["small.ipa": src])
		defer { server.shutdown() }

		let out = Fixtures.dir.appendingPathComponent("full.out").path
		let r = sh("curl -sS -D - -o \(q(out)) \(server.http)/file/small.ipa")
		XCTAssertEqual(r.status, 0, r.err)
		let headers = r.out.lowercased()
		XCTAssertTrue(headers.contains("http/1.1 200"), headers)
		XCTAssertTrue(headers.contains("content-length: \(size)"), headers)
		XCTAssertTrue(headers.contains("accept-ranges: bytes"), headers)
		XCTAssertTrue(headers.contains("content-type: application/octet-stream"), headers)
		XCTAssertEqual(sha256(file: out), sha256(file: src.path))

		XCTAssertTrue(server.recorder.waitForOutcomes(1))
		guard case .completed(let bytes) = server.recorder.outcomes[0].0 else { return XCTFail("not completed") }
		XCTAssertEqual(bytes, size)
		XCTAssertEqual(server.recorder.outcomes[0].1, size)
		XCTAssertEqual(server.recorder.starts[0].length, size)
		XCTAssertNil(server.recorder.starts[0].range)
	}

	func testPartialResponsesAndHashes() throws {
		let src = Fixtures.small
		let size = (try FileManager.default.attributesOfItem(atPath: src.path)[.size] as! NSNumber).int64Value
		let server = try TestServer(files: ["small.ipa": src])
		defer { server.shutdown() }

		let cases: [(header: String, offset: Int64, length: Int64)] = [
			("bytes=0-0", 0, 1),
			("bytes=1000-1999", 1000, 1000),
			("bytes=5000000-", 5_000_000, size - 5_000_000),
			("bytes=-12345", size - 12345, 12345),
			("bytes=\(size - 10)-\(size + 9999)", size - 10, 10),
		]
		for (i, c) in cases.enumerated() {
			let out = Fixtures.dir.appendingPathComponent("part\(i).out").path
			let r = sh("curl -sS -D - -H 'Range: \(c.header)' -o \(q(out)) \(server.http)/file/small.ipa")
			XCTAssertEqual(r.status, 0, r.err)
			let h = r.out.lowercased()
			XCTAssertTrue(h.contains("http/1.1 206"), "\(c.header): \(h)")
			XCTAssertTrue(h.contains("content-length: \(c.length)"), "\(c.header): \(h)")
			XCTAssertTrue(h.contains("content-range: bytes \(c.offset)-\(c.offset + c.length - 1)/\(size)"), "\(c.header): \(h)")
			XCTAssertEqual(sha256(file: out), sha256(file: src.path, offset: c.offset, length: c.length), c.header)
		}
		XCTAssertTrue(server.recorder.waitForOutcomes(cases.count))
		for (i, c) in cases.enumerated() {
			let match = server.recorder.outcomes.contains { if case .completed(let b) = $0.0 { return b == c.length && $0.1 == c.length }; return false }
			XCTAssertTrue(match, "no completed outcome with \(c.length) bytes for \(cases[i].header)")
		}
	}

	func testUnsatisfiableRangeIs416() throws {
		let src = Fixtures.small
		let size = (try FileManager.default.attributesOfItem(atPath: src.path)[.size] as! NSNumber).int64Value
		let server = try TestServer(files: ["small.ipa": src])
		defer { server.shutdown() }
		let r = sh("curl -sS -D - -o /dev/null -H 'Range: bytes=\(size)-' \(server.http)/file/small.ipa")
		let h = r.out.lowercased()
		XCTAssertTrue(h.contains("http/1.1 416"), h)
		XCTAssertTrue(h.contains("content-range: bytes */\(size)"), h)
	}

	func testMissingFileIs404AndEmptyFileIs200() throws {
		let empty = Fixtures.dir.appendingPathComponent("empty.ipa")
		FileManager.default.createFile(atPath: empty.path, contents: Data())
		let server = try TestServer(files: ["empty.ipa": empty, "gone.ipa": Fixtures.dir.appendingPathComponent("nope.ipa")])
		defer { server.shutdown() }
		let r1 = sh("curl -sS -D - -o /dev/null \(server.http)/file/gone.ipa")
		XCTAssertTrue(r1.out.contains("404"), r1.out)
		let r2 = sh("curl -sS -D - -o /dev/null \(server.http)/file/empty.ipa")
		XCTAssertTrue(r2.out.lowercased().contains("content-length: 0"), r2.out)
		XCTAssertTrue(r2.out.contains(" 200"), r2.out)
	}

	// MARK: Interrupted transfer

	func testInterruptedTransferIsReportedAndHandlesAreClosed() throws {
		let src = Fixtures.large(megabytes: 250)
		let server = try TestServer(files: ["big.ipa": src])
		defer { server.shutdown() }
		// warm up so lazily opened descriptors (curl probes, listeners) are part of the baseline
		_ = sh("curl -sS -o /dev/null \(server.http)/health")
		Thread.sleep(forTimeInterval: 0.3)
		let baseline = openFDCount()
		let before = lsofSnapshot()

		// ~5 MB/s for 1 s => aborted after a few MB of a 250 MB body
		let r = sh("curl -sS --limit-rate 5m --max-time 1 -o /dev/null \(server.http)/file/big.ipa")
		XCTAssertNotEqual(r.status, 0, "curl should have timed out")

		XCTAssertTrue(server.recorder.waitForOutcomes(1), "observer never got an outcome")
		let expected = server.recorder.outcomes[0].1
		switch server.recorder.outcomes[0].0 {
		case .interrupted(let bytes, _):
			XCTAssertLessThan(bytes, expected)
			print("interrupted after \(bytes) of \(expected) bytes")
		case .completed:
			XCTFail("transfer should have been interrupted")
		}

		let deadline = Date().addingTimeInterval(5)
		var now = openFDCount()
		while now > baseline, Date() < deadline { Thread.sleep(forTimeInterval: 0.1); now = openFDCount() }
		if now > baseline {
			let after = lsofSnapshot()
			print("FD_DIFF new descriptors: \(after.filter { !before.contains($0) })")
		}
		XCTAssertLessThanOrEqual(now, baseline, "file descriptors leaked: baseline \(baseline), now \(now)")
	}

	// MARK: Large files (plain HTTP)

	func testLarge250MB() throws { try largeDownload(megabytes: 250, rssLimitMB: 100) }

	func testLarge500MB() throws { try largeDownload(megabytes: 500, rssLimitMB: 100) }

	private func largeDownload(megabytes: Int, rssLimitMB: Double) throws {
		try XCTSkipIf(skipLarge, "KSIGN_SKIP_LARGE=1")
		let src = Fixtures.large(megabytes: megabytes)
		let total = Int64(megabytes) << 20
		let expectedHash = sha256(file: src.path)
		let server = try TestServer(files: ["big.ipa": src])
		defer { server.shutdown() }

		let out = Fixtures.dir.appendingPathComponent("big-\(megabytes).out").path
		let start = Date()
		let (r, peakMB) = withRSSSampling {
			sh("curl -sS -o \(q(out)) -w '%{http_code} %{size_download}' \(server.http)/file/big.ipa")
		}
		let secs = Date().timeIntervalSince(start)
		XCTAssertEqual(r.out, "200 \(total)", r.err)
		XCTAssertEqual(sha256(file: out), expectedHash)
		print("RSS_REPORT \(megabytes)MB full download: peak RSS growth \(String(format: "%.1f", peakMB)) MB, \(String(format: "%.1f", secs)) s")
		XCTAssertLessThan(peakMB, rssLimitMB, "memory grew with file size")
		XCTAssertTrue(server.recorder.waitForOutcomes(1))
		if case .completed(let b) = server.recorder.outcomes[0].0 { XCTAssertEqual(b, total) } else { XCTFail("not completed") }
		try? FileManager.default.removeItem(atPath: out)

		// Explicit tail range.
		let tailOffset = total - 50_000_000
		let tail = Fixtures.dir.appendingPathComponent("tail-\(megabytes).out").path
		let rt = sh("curl -sS -H 'Range: bytes=\(tailOffset)-' -o \(q(tail)) -w '%{http_code} %{size_download}' \(server.http)/file/big.ipa")
		XCTAssertEqual(rt.out, "206 50000000", rt.err)
		XCTAssertEqual(sha256(file: tail), sha256(file: src.path, offset: tailOffset, length: 50_000_000))
		try? FileManager.default.removeItem(atPath: tail)

		// Resume: truncated partial file + `curl -C -`
		let part = Fixtures.dir.appendingPathComponent("resume-\(megabytes).out").path
		let first = sh("curl -sS -r 0-104857599 -o \(q(part)) \(server.http)/file/big.ipa")
		XCTAssertEqual(first.status, 0, first.err)
		let resumed = sh("curl -sS -C - -o \(q(part)) -w '%{http_code} %{size_download}' \(server.http)/file/big.ipa")
		XCTAssertEqual(resumed.out, "206 \(total - 104_857_600)", resumed.err)
		XCTAssertEqual(sha256(file: part), expectedHash, "resumed download differs from source")
		try? FileManager.default.removeItem(atPath: part)
	}
}
