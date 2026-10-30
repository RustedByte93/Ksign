//
//  Server+Compute.swift
//  feather
//
//  Created by samara on 22.08.2024.
//  Copyright © 2024 Lakr Aream. All Rights Reserved.
//  ORIGINALLY LICENSED UNDER GPL-3.0, MODIFIED FOR USE FOR FEATHER
//

import Foundation
import UIKit.UIGraphicsImageRenderer

extension ServerInstaller {
	var plistEndpoint: URL {
		var comps = URLComponents()
		comps.scheme = ServerInstaller.getServerMethod() == 1 ? "http" : "https"
		comps.host = Self.sni
		comps.path = "/\(id).plist"
		comps.port = port
		return comps.url!
	}

	var payloadEndpoint: URL {
		var comps = URLComponents()
		comps.scheme = ServerInstaller.getServerMethod() == 1 ? "http" : "https"
		comps.host = Self.sni
		comps.path = "/\(id).ipa"
		comps.port = port
		return comps.url!
	}
	
	var pageEndpoint: URL {
		var comps = URLComponents()
		comps.scheme = ServerInstaller.getServerMethod() == 1 ? "http" : "https"
		comps.host = Self.sni
		comps.path = "/install"
		comps.port = port
		return comps.url!
	}
	
	var externalServerLink: String {
		let baseUrl = "https://api.palera.in/genPlist?bundleid=\(app.identifier!)&name=\(app.name!)&version=\(app.version!)&fetchurl=\(self.payloadEndpoint.absoluteString)"
		let encodedBaseUrl = baseUrl.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
		let finalEncodedUrl = encodedBaseUrl.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
		
		return finalEncodedUrl
	}

	var iTunesLink: String {
		_iTunesLink(with: plistEndpoint.absoluteString)
	}
	
	var iTunesLinkExternal: String {
		_iTunesLink(with: externalServerLink)
	}
	
	private func _iTunesLink(with url: String) -> String {
		return "itms-services://?action=download-manifest&url=\(url)"
	}

	var displayImageSmallEndpoint: URL {
		var comps = URLComponents()
		comps.scheme = Self.getServerMethod() == 1 ? "http" : "https"
		comps.host = Self.sni
		comps.path = "/app57x57.png"
		comps.port = port
		return comps.url!
	}

	var displayImageLargeEndpoint: URL {
		var comps = URLComponents()
		comps.scheme = Self.getServerMethod() == 1 ? "http" : "https"
		comps.host = Self.sni
		comps.path = "/app512x512.png"
		comps.port = port
		return comps.url!
	}
	
	var displayImageSmallData: Data {
		_createIcon(57)
	}
	
	var displayImageLargeData: Data {
		_createIcon(512)
	}
	
	private func _createIcon(_ r: CGFloat) -> Data {
		let renderer = UIGraphicsImageRenderer(size: .init(width: r, height: r))
		let image = renderer.image { ctx in
			UIColor.accent.setFill()
			ctx.fill(.init(x: 0, y: 0, width: r, height: r))
		}
		return image.pngData()!
	}

	/// Landing page opened in Safari. Shows a real, user-tappable install link (iOS is stricter about
	/// `itms-services` redirects that happen without a user gesture) and also tries the redirect itself.
	/// Fully Local points at the local HTTPS manifest; Semi Local needs the external HTTPS manifest proxy
	/// because iOS refuses plain-HTTP manifests.
	var html: String {
		let link = Self.getServerMethod() == 1 ? iTunesLinkExternal : iTunesLink
		let href = link
			.replacingOccurrences(of: "&", with: "&amp;")
			.replacingOccurrences(of: "\"", with: "&quot;")
		let title = (app.name ?? "App")
			.replacingOccurrences(of: "&", with: "&amp;")
			.replacingOccurrences(of: "<", with: "&lt;")
			.replacingOccurrences(of: ">", with: "&gt;")
		return """
		<!DOCTYPE html>
		<html>
		<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Install \(title)</title>
		<style>
		body{background:#000;color:#fff;font-family:-apple-system,sans-serif;text-align:center;padding-top:30vh}
		a.btn{display:inline-block;margin-top:24px;padding:16px 36px;border-radius:14px;background:#0a84ff;color:#fff;font-size:20px;text-decoration:none}
		</style>
		</head>
		<body>
		<h2>\(title)</h2>
		<a class="btn" href="\(href)">Install</a>
		<script>setTimeout(function(){window.location.href=document.querySelector("a.btn").href;},400)</script>
		</body>
		</html>
		"""
	}

	/// Throws instead of serving an empty/invalid manifest (iOS rejects those without any visible reason).
	func installManifestResult() throws -> Data {
		try LocalInstallerManifest.make(
			bundleIdentifier: app.identifier,
			bundleVersion: app.version,
			title: app.name,
			packageURL: payloadEndpoint,
			displayImageURL: displayImageSmallEndpoint
		)
	}
}
