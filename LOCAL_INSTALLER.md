# Local HTTPS installer: root cause, fix, diagnostics, build

Fork of Ksign 1.6.1 (+ `c14dedc`). The signing engine (Zsign), signing certificates, provisioning, entitlements and the bundle identifier are untouched.

## 1. Root cause of `"*.backloop.dev" certificate is not standards compliant`

| Item | Finding |
|---|---|
| Producing code | `LocalTLSIdentity.inspect()` → `SecTrustEvaluateWithError`, SSL policy for the hostname, the leaf itself as the only anchor (`SecTrustSetAnchorCertificates` + `AnchorCertificatesOnly`). Previously fatal: it aborted server start. |
| Error | `NSOSStatusErrorDomain` **-67901** (`errSecCertificateValidityPeriodTooLong`), localized as "certificate is not standards compliant". |
| Real cause | The published backloop.dev certificate is valid **3650 days**. Security.framework rejects TLS server certificates valid for more than **825 days** (https://support.apple.com/en-us/103769). |
| Not the cause | Wildcard SAN, EKU, key type, key match, hostname logic, expiry. OpenSSL accepts the certificate. The check runs before the hostname check, which is why a wrong host also returned -67901. |

Reproduced with a Swift harness using the same calls as the app (macOS Security.framework):

| Case (explicit anchor, SSL policy, host `ksign.backloop.dev`) | Result |
|---|---|
| Published backloop.dev cert (RSA-2048, 3650 d, self-signed) | **FAIL -67901** |
| Self-signed EC leaf, 3650 d | FAIL -67901 |
| Self-signed EC leaf, 825 d / 398 d | PASS |
| Private CA + leaf 3650 d | FAIL -67901 |
| Private CA + leaf 825 d / 398 d | PASS |
| Name-constrained CA + leaf (this project's PKI), correct host | PASS |
| Same, wrong host | FAIL -67602 |
| Same CA, leaf outside the name constraint | FAIL -67689 |
| Same, no anchor (system trust only) | FAIL -25318 "not trusted" |

Two things this does **not** establish:

- Apple documents that the 825-day rule does not apply to certificates anchored in a user-/administrator-added root. The harness used `SecTrustSetAnchorCertificates`, which is neither. Whether iOS 27.0.1 applies the rule to the published cert when it is trusted via Certificate Trust Settings is **not tested** (no device available here).
- Even if it would pass, the published cert's private key is public. Trusting it system-wide lets anyone who controls DNS/network for any `*.backloop.dev` name impersonate it. That is why Option B (private CA) is the default, not a repair of the preflight.

## 2. What changed

| Area | Change |
|---|---|
| `Scripts/make-local-pki.sh` (new) | Private CA (EC P-256, **name-constrained to `ksign.backloop.dev`**, CA key kept **outside** the repo and IPA, default `~/.ksign-pki`, mode 600) + leaf (EC P-256, SAN, serverAuth, CA:FALSE, **365 days**, hard cap 825). Writes `server.crt`, `server.pem` (leaf key), `commonName.txt`, `KsignLocalCA.crt/.cer/.mobileconfig` to `deps/`. Re-running = renewal under the same CA. `--ephemeral` destroys the CA key. Verifies chain, hostname, EKU, key match, and refuses a CA key in the output dir. |
| `makefile` | `deps` runs the PKI script. |
| `LocalTLSIdentity.swift` | Staged inspection: parse (subject, issuer, SAN, validity, days) → key match → structural check. Structural failure is **reported, not fatal**; only "cannot build a server" (unparseable, key mismatch, expired) blocks. Public backloop cert is recognised and flagged as shared-key. |
| `IPAResponder.swift` (new) | Streaming responder: constant memory, Content-Length, single Range (206/416), backpressure, handle cleanup, exact byte accounting. |
| `LocalInstallerManifest.swift` (new) | Manifest build + validation (https, host, **bound port**, bundle id). Empty bundle id throws instead of serving an empty manifest. |
| `LocalInstallerDiagnostics.swift`, `LocalInstallerRedactor.swift`, `LocalInstallerReport.swift` (new/rewritten) | Bounded (500) thread-safe event log with operation id, component, domain/code, underlying error, pipeline state, host/port, metadata; redaction of UDIDs, key blocks, home paths, passwords; text + JSON report; zip bundle. |
| `LocalInstallerSelfTest.swift` (new) | 12-stage runner: PASS / FAIL / NOT TESTED with reason and next action. Never relaxes TLS verification. |
| `LocalInstallerDiagnosticsView.swift` | Run Full Diagnostics, Test Certificate, Test HTTPS Listener, Test System TLS Trust, Test Manifest, Test IPA Endpoint, Copy Full Report, Export Diagnostic Bundle, Export Trust Profile. |
| `ServerInstaller*.swift` | Events at init/TLS identity/bind attempt/listener/IPA stream/background expiry; port 4431 then random fallback with the **actual** port in every URL; `handOffToiOS` = strict HTTPS check (system trust) before opening `itms-services`; no success is recorded for the hand-off. |
| `InstallPreviewView`, `BulkInstallProgressView` | Use the trust-gated hand-off; a refusal shows the exact error and next action. |
| `.github/workflows/build-local-tls-ipa.yml` | Runs the macOS tests, builds, verifies the IPA (chain, ≤ 825 days, key match, no CA key), uploads the IPA and the public CA artifacts. |
| `Scripts/fetch-local-tls.sh` | Marked deprecated; not used. |
| `Tests/LocalInstaller/` (new) | macOS SwiftPM tests of the real source files (see section 6). |

## 3. Certificate architecture and its risks

- **CA** (`~/.ksign-pki/ca.key`): protect it like a signing key. Never commit, never copy into `deps/`, never put in the IPA. The script and CI check for it. Name constraint means even a stolen CA key can only mint certificates for `ksign.backloop.dev`.
- **Leaf key** (`server.pem`) **is inside the IPA**. Anyone who extracts it from your IPA can impersonate `ksign.backloop.dev` to a device that trusts **your** CA. Scope: only devices where you installed your CA profile, and only that hostname. Do not share IPAs built from your CA publicly; each owner should run the script themselves (per-owner identity, not shared with the world as the published cert is). A true per-device key would need on-device X.509 generation plus an on-device CA (so the CA key would live on the phone); not implemented.
- **Renewal**: leaf lasts 365 days. Re-run `sh Scripts/make-local-pki.sh --out deps` (same CA, no re-trust) and rebuild. CA lasts 5 years; the script refuses to reuse a CA with < 30 days left.
- DNS: `ksign.backloop.dev` → 127.0.0.1 is controlled by backloop.dev. They cannot obtain a certificate that your phone trusts, but they can make the name resolve elsewhere (installs then fail; no data is exposed because nothing trusted is presented).

## 4. Trusting the CA on the iPhone (nothing is installed automatically)

1. Settings ▸ Installation ▸ Local Installer Diagnostics ▸ **Export Trust Profile**, save to Files.
2. Open `KsignLocalCA.mobileconfig` from Files ▸ Settings ▸ **Profile Downloaded** ▸ Install.
3. Settings ▸ General ▸ About ▸ **Certificate Trust Settings** ▸ enable "Ksign Local Installer CA".
4. Run **Test System TLS Trust**. It must say PASS before installing.

## 5. Updating the installed fork without losing data

The bundle identifier is unchanged. iOS keeps the app container (certificates, provisioning, stored IPAs, settings, signing history) only when the new build is installed **over** the existing app with the **same signing team and bundle id**. So: sign the new `packages/Ksign.ipa` with the same certificate/team that signed the installed one, and install it as an update (it cannot update itself through its own installer: Ksign blocks that case). If it is signed by a different team, iOS treats it as a different app or refuses; do **not** delete the installed app first. Back up certificates and IPAs via Files before any install. Untested on the device.

## 6. Verification status

**Verified by source inspection:** error origin and flow; bundle id/signing code untouched (`git diff` has no `Zsign`, `project.pbxproj` or entitlement changes); CA key never written next to the app payload.

**Verified by automated tests (macOS, `Tests/LocalInstaller`, `swift test`):**
- `IPAResponder`: range table, 200/206/416 headers and SHA-256, empty file, 404, byte accounting, interrupted transfer returns file descriptors to baseline.
- 250 MB and 500 MB full downloads, 50 MB tail range, `curl -C -` resume: exact size and hash. Peak RSS growth of the serving process 0.2 MB (250 MB) and 0.5 MB (500 MB) in a debug build.
- Certificate/manifest/redaction tests: see the result line in section 7.

**Verified by real TLS handshake (macOS, strict verification):** `curl --cacert` succeeds for `ksign.backloop.dev`; without `--cacert` it fails (exit 60); wrong hostname fails (exit 60); `openssl s_client` → `Verify return code: 0 (ok)` and presented leaf fingerprint equals `server.crt`; TLS 1.2 accepted, TLS 1.0/1.1 refused; 100 MB Range over TLS correct.

**Compiled:** `make` → arm64, iphoneos SDK 27.1, Release: BUILD SUCCEEDED (`packages/Ksign.ipa`, platform iOS, minos 16.0).

**Not yet verified:**
- Anything on a physical iPhone: new self-test results, iOS accepting the CA via profile, `itms-services` hand-off, installation on iOS 27.0.1.
- Whether installd/itunesstored can fetch from a loopback server inside Ksign while Ksign is backgrounded. Keep Ksign in the foreground (silent-audio keep-alive exists in the app); the server logs `background.expired` if iOS suspends it. No unrestricted background execution is assumed.
- The Apple user-root exemption from the 825-day rule (section 1).
- Server-side TLS handshake failures: only visible through the NIO logger (best effort), not as first-class events.
- GitHub Actions: YAML written, **not run**.
- Port-fallback (4431 → random): logic present and logged, exercised only by code reading.

## 7. Using the diagnostics

Order of checks when an install fails: DNS Resolution → Certificate Loaded → Private Key Match → Certificate Standards → Server Identity → HTTPS Listener → Presented Certificate → **System TLS Trust** → GET /health → Manifest → IPA → OTA (always NOT TESTED; only iOS knows). NOT TESTED means "not reached", never "failed". A PASS means this app made a strictly validated HTTPS request to its own diagnostic server; it does not prove an installation. **Copy Full Report** and **Export Diagnostic Bundle** (`report.txt`, `report.json`, `events.json`, public CA cert) never contain private keys, signing credentials, UDIDs or provisioning data.

## 8. Build

```sh
sh Scripts/make-local-pki.sh --out deps   # or let `make` do it
make                                       # packages/Ksign.ipa (ad-hoc signed; re-sign with YOUR Apple identity)
cd Tests/LocalInstaller && swift test      # KSIGN_SKIP_LARGE=1 to skip the 250/500 MB cases
```

CI secrets for a stable CA: `KSIGN_CA_CERT_B64`, `KSIGN_CA_KEY_B64` (base64 of `ca.crt` / `ca.key`). Without them CI uses an ephemeral CA and the phone must trust each build's new CA.

## 9. Limits that remain

- First install of this fork needs an existing install path (it cannot install itself initially).
- OTA install still requires a valid Apple signature for the device, a CA trusted on the device, and iOS allowing `itms-services`. None of that is bypassed.
