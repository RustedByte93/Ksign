//
//  Server+TLS.swift
//  feather
//
//  Created by samara on 22.08.2024.
//  Copyright © 2024 Lakr Aream. All Rights Reserved.
//  ORIGINALLY LICENSED UNDER GPL-3.0, MODIFIED FOR USE FOR FEATHER
//

import Foundation
import NIOSSL
import NIOTLS
import Vapor
import SystemConfiguration.CaptiveNetwork

// MARK: - Class extension: TLS/Setup
extension ServerInstaller {
	// MARK: Setup
	private static let env: Environment = {
		let env = try! Environment.detect()
		// Console output as before, plus TLS-related lines (the only server-side handshake evidence) into the diagnostics log.
		LoggingSystem.bootstrap { label in
			MultiplexLogHandler([StreamLogHandler.standardOutput(label: label), DiagnosticsLogHandler(label: label)])
		}
		return env
	}()

	/// Builds (but does not start) the HTTP(S) server.
	///
	/// Fully Local (method 0) ALWAYS requires a valid TLS identity: if none can be loaded this throws,
	/// instead of silently serving plain HTTP behind an `https://` URL (the previous behaviour).
	static func setupApp(port: Int, forceTLSIdentity: LocalTLSIdentity? = nil) throws -> Application {
		let tls: TLSConfiguration?
		if getServerMethod() != 1 || forceTLSIdentity != nil {
			let identity = try forceTLSIdentity ?? LocalTLSIdentity.resolve()
			tls = try identity.tlsConfiguration()
			LocalInstallerDiagnostics.shared.log(
				component: "tls", event: "tls.identity.configured",
				message: "server TLS configured (TLS >= 1.2), source=\(identity.source.rawValue), sha256=\(identity.report.fingerprint)",
				hostname: identity.hostname, port: port
			)
		} else {
			tls = nil
		}

		let app = Application(env)
		app.threadPool = .init(numberOfThreads: 1)

		if let tls {
			app.http.server.configuration.tlsConfiguration = tls
		}

		app.http.server.configuration.hostname = (forceTLSIdentity != nil) ? "127.0.0.1" : bindAddress
		app.http.server.configuration.tcpNoDelay = true
		app.http.server.configuration.port = port
		app.routes.defaultMaxBodySize = "128mb"
		app.routes.caseInsensitive = false

		return app
	}

	// MARK: Files/IP

	/// Fully Local binds to loopback only (the hostname resolves to 127.0.0.1); the IPA is not exposed
	/// to the LAN. Semi Local needs the Wi-Fi address and keeps the previous 0.0.0.0 binding.
	static var bindAddress: String {
		getServerMethod() == 1 ? "0.0.0.0" : "127.0.0.1"
	}

	/// Hostname used in every installer URL.
	/// Fully Local: a concrete label under the certificate's wildcard (never a literal `*`).
	static var sni: String {
		let localhost = "127.0.0.1"

		if getServerMethod() == 1 {
			return !ServerInstaller.getIPFix()
			? (getLocalAddress() ?? localhost)
			: localhost
		} else {
			return LocalTLSIdentity.resolveHostname()
		}
	}
}

extension ServerInstaller {
	static func getLocalAddress() -> String? {
		var address: String?
		var ifaddr: UnsafeMutablePointer<ifaddrs>?
		
		if getifaddrs(&ifaddr) == 0 {
			var ptr = ifaddr
			while ptr != nil {
				let interface = ptr!.pointee
				let addrFamily = interface.ifa_addr.pointee.sa_family
				
				if addrFamily == UInt8(AF_INET) {
					
					let name = String(cString: interface.ifa_name)
					if name == "en0" || name == "pdp_ip0" {
						
						var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
						if getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len),
									   &hostname, socklen_t(hostname.count),
									   nil, socklen_t(0), NI_NUMERICHOST) == 0 {
							address = String(cString: hostname)
						}
						
					}
				}
				ptr = ptr!.pointee.ifa_next
			}
			freeifaddrs(ifaddr)
		}
		
		return address
	}
}
