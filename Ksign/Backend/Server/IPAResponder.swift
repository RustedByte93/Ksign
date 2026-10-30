//
//  IPAResponder.swift
//  Ksign
//
//  Streams a file from disk as an HTTP response: constant memory, Content-Length, single-range
//  requests (206 / 416), real backpressure (each chunk waits for the previous write), accurate byte
//  accounting and file-handle cleanup on every path. Depends only on Vapor/NIO so that the same code
//  is exercised by the macOS test package in Tests/LocalInstaller.
//

import Foundation
import Vapor
import NIOCore
import NIOPosix

enum IPAResponder {
	static let chunkSize = 512 * 1024

	enum Outcome {
		case completed(bytes: Int64)
		case interrupted(bytes: Int64, error: Error)
	}

	struct Observer {
		var started: @Sendable (_ rangeHeader: String?, _ offset: Int64, _ length: Int64, _ total: Int64) -> Void = { _, _, _, _ in }
		var finished: @Sendable (_ outcome: Outcome, _ expected: Int64) -> Void = { _, _ in }
		init() {}
	}

	enum RangeSelection: Equatable {
		case whole
		case partial(offset: Int64, length: Int64)
		case unsatisfiable
	}

	/// RFC 9110 single byte range. Syntax we do not understand, other units and multi-range requests are
	/// answered with the whole representation (which the RFC allows); an unsatisfiable range yields 416.
	static func selectRange(header: String?, size: Int64) -> RangeSelection {
		guard let header, header.lowercased().hasPrefix("bytes=") else { return .whole }
		let spec = header.dropFirst("bytes=".count).trimmingCharacters(in: .whitespaces)
		guard !spec.contains(",") else { return .whole }
		let parts = spec.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
		guard parts.count == 2 else { return .whole }

		if parts[0].isEmpty {
			guard let suffix = Int64(parts[1]), suffix > 0 else { return .whole }
			guard size > 0 else { return .unsatisfiable }
			let length = min(suffix, size)
			return .partial(offset: size - length, length: length)
		}
		guard let first = Int64(parts[0]), first >= 0 else { return .whole }
		var last = size - 1
		if !parts[1].isEmpty {
			guard let requestedLast = Int64(parts[1]) else { return .whole }
			guard requestedLast >= first else { return .whole }
			last = min(requestedLast, size - 1)
		}
		guard first < size else { return .unsatisfiable }
		return .partial(offset: first, length: last - first + 1)
	}

	static func response(for req: Request, fileURL: URL, observer: Observer = Observer()) -> Response {
		guard
			let attributes = try? FileManager.default.attributesOfItem(atPath: fileURL.path),
			let size = (attributes[.size] as? NSNumber)?.int64Value
		else {
			return Response(status: .notFound)
		}

		let rangeHeader = req.headers.first(name: .range)
		var offset: Int64 = 0
		var length = size
		var status: HTTPResponseStatus = .ok
		var contentRange: String?

		switch selectRange(header: rangeHeader, size: size) {
		case .whole:
			break
		case .partial(let o, let l):
			offset = o; length = l; status = .partialContent
			contentRange = "bytes \(o)-\(o + l - 1)/\(size)"
		case .unsatisfiable:
			let response = Response(status: .rangeNotSatisfiable)
			response.headers.replaceOrAdd(name: .contentRange, value: "bytes */\(size)")
			return response
		}

		let response = Response(status: status)
		response.headers.replaceOrAdd(name: .contentType, value: "application/octet-stream")
		response.headers.replaceOrAdd(name: .acceptRanges, value: "bytes")
		response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
		if let contentRange { response.headers.replaceOrAdd(name: .contentRange, value: contentRange) }

		observer.started(rangeHeader, offset, length, size)

		let path = fileURL.path
		let startOffset = offset
		let byteCount = length
		let eventLoop = req.eventLoop
		let io = req.application.fileio
		let allocator = req.application.allocator

		response.body = .init(stream: { writer in
			let counter = ByteCounter()

			func finish(_ result: Result<Void, Error>) {
				let sent = counter.value
				switch result {
				case .success where sent == byteCount:
					writer.write(.end, promise: nil)
					observer.finished(.completed(bytes: sent), byteCount)
				case .success:
					let error = Abort(.internalServerError, reason: "file changed during transfer: sent \(sent) of \(byteCount) bytes")
					writer.write(.error(error), promise: nil)
					observer.finished(.interrupted(bytes: sent, error: error), byteCount)
				case .failure(let error):
					writer.write(.error(error), promise: nil)
					observer.finished(.interrupted(bytes: sent, error: error), byteCount)
				}
			}

			guard byteCount > 0 else { finish(.success(())); return }

			let handle: NIOFileHandle
			do { handle = try NIOFileHandle(path: path) } catch { finish(.failure(error)); return }

			io.readChunked(
				fileHandle: handle,
				fromOffset: startOffset,
				byteCount: Int(byteCount),
				chunkSize: chunkSize,
				allocator: allocator,
				eventLoop: eventLoop
			) { chunk in
				counter.add(Int64(chunk.readableBytes))
				return writer.write(.buffer(chunk))
			}.whenComplete { result in
				try? handle.close()
				finish(result)
			}
		}, count: Int(byteCount), byteBufferAllocator: req.byteBufferAllocator)

		return response
	}
}

private final class ByteCounter: @unchecked Sendable {
	private let lock = NSLock()
	private var total: Int64 = 0
	var value: Int64 { lock.lock(); defer { lock.unlock() }; return total }
	func add(_ n: Int64) { lock.lock(); total += n; lock.unlock() }
}
