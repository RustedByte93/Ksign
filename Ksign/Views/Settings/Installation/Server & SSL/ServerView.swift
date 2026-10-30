//
//  ServerView.swift
//  Feather
//
//  Created by samara on 6.05.2025.
//

import SwiftUI
import NimbleViews

struct ServerView: View {
	@AppStorage("Feather.ipFix") private var _ipFix: Bool = false
	@AppStorage("Feather.serverMethod") private var _serverMethod: Int = 0
	
	private let _serverMethods: [String] = [
		.localized("Fully Local"), 
		.localized("Semi Local")
	]
	
	var body: some View {
		Group {
			Section {
				Picker(.localized("Installation Type"), systemImage: "server.rack", selection: $_serverMethod) {
					ForEach(_serverMethods.indices, id: \.self) { index in
						Text(_serverMethods[index]).tag(index)
					}
				}
				Toggle(.localized("Only use localhost address"), systemImage: "lifepreserver", isOn: $_ipFix)
					.disabled(_serverMethod != 1)
			} footer: {
				Text("Fully Local serves the manifest and IPA over HTTPS from this device using the bundled (or your own) TLS certificate. No external service is used. Semi Local needs an external HTTPS manifest proxy.")
			}
			
			// The old "Update SSL Certificates" action downloaded https://backloop.dev/pack.json, which is the
			// revoked + expired certificate. The certificate is now bundled at build time and validated at launch.
			Section {
				NavigationLink {
					LocalInstallerDiagnosticsView()
				} label: {
					Label("Local Installer Diagnostics", systemImage: "stethoscope")
				}
			}
		}
		.onChange(of: _serverMethod) { _ in
			UIAlertController.showAlertWithRestart(
				title: .localized("Restart Required"),
				message: .localized("These changes require a restart of the app")
			)
		}
	}
}
