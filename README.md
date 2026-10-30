
<img src="https://github.com/user-attachments/assets/986892f9-c32f-448d-a24e-ba8659203fbf" height="200">

# Ksign 
[![GitHub Release](https://img.shields.io/github/v/release/nyasami/ksign?style=for-the-badge&color=3c94fc)](https://github.com/nyasami/ksign/releases/latest) 
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nyasami/ksign/total?style=for-the-badge&color=6bc563)](https://github.com/nyasami/ksign/releases)

Yet another codesigning app, have you ever wondered what if Feather and Esign had a child?

## iOS 27 fix: Fully Local install (this fork)

> Unofficial community fork of [Nyasami/Ksign](https://github.com/Nyasami/Ksign) 1.6.1. It only touches the local installer; the signing engine is unchanged.

**Problem.** "Fully Local" install got stuck on *Ready* and Install could not be tapped:
- `make` downloaded the TLS certificate from URLs that now return 404, saved the error page as `server.crt` and ignored the failure.
- The hostname was `*.backloop.dev`, which is not a connectable host.
- A valid certificate was overwritten on every launch with a revoked one.
- The server silently fell back to plain HTTP behind an `https://` URL.
- Even after fixing that, the public backloop.dev certificate is valid for 10 years. Apple rejects it with `-67901` ("not standards compliant"): TLS server certificates may not be valid for more than 825 days. An in-app preflight treated that as fatal, so the server never started.

**Fix.**
- This fork does **not** use the public backloop.dev certificate. It only uses the *name* `ksign.backloop.dev`, which resolves to `127.0.0.1`, so the iPhone talks to the server running inside the app.
- `Scripts/make-local-pki.sh` creates your own private CA, name-constrained to `ksign.backloop.dev`, and a 365-day leaf certificate. The CA key stays on your machine (`~/.ksign-pki`), never in the repo or the IPA.
- You install `KsignLocalCA.mobileconfig` once and enable it under *Settings > General > About > Certificate Trust Settings*. Nothing is installed or trusted automatically.
- Install is only handed to iOS after a strict HTTPS request to the local server succeeds with normal system trust. No TLS verification is bypassed.
- IPA streaming from disk with Range support (tested with 250 MB and 500 MB files).
- *Settings > Installation > Local Installer Diagnostics*: staged self-test (PASS / FAIL / NOT TESTED) and a redacted report export.

**Using it.**
1. `make` (generates the certificates and builds `packages/Ksign.ipa`), then sign that IPA with your own certificate and install it.
2. Trust your local CA once (see [Trusting the local CA](#trusting-the-local-ca-one-time-required) below). Then run *Test System TLS Trust* and wait for PASS.
3. Install an app. iOS may show a system confirmation popup; confirm it (for example tap Install / Continue) and the installation proceeds.
4. Keep the app in the foreground while it installs.

### Trusting the local CA (one time, required)

Without this step the iPhone does not trust the local HTTPS server and the install never starts. The file is **not in this repo**: `make` generates `KsignLocalCA.mobileconfig` for you from *your own* CA and puts it inside the IPA. It only lets the phone trust certificates for `ksign.backloop.dev`; it has nothing to do with signing the IPA.

1. In the app: *Settings > Installation > Local Installer Diagnostics > Export Trust Profile*, and save the file to the Files app.
2. Open `KsignLocalCA.mobileconfig` from Files. iOS shows *Profile Downloaded*; go to *Settings* and tap **Install**.
3. *Settings > General > About > Certificate Trust Settings*: switch on **Ksign Local Installer CA**.
4. Back in the app, run *Test System TLS Trust*. It must say PASS before you install anything.

You only need to do this once. Renewing the certificate (it lasts a year) does not need a new profile as long as you keep your CA at `~/.ksign-pki`; if you create a new CA, repeat the steps above.

**Testing.** 28 automated tests on macOS (`cd Tests/LocalInstaller && swift test`), real TLS handshakes with strict verification, arm64 build. Confirmed working on a physical iPhone running iOS 27.0.1. That is one device; other devices and iOS versions are untested.

**Limitations.** The trust profile is required. The leaf key is inside the IPA, so build with your own CA and do not share your IPA. Details and the root-cause analysis are in [LOCAL_INSTALLER.md](LOCAL_INSTALLER.md).

## Why?
Since Esign is end of service so people been moving to other signing apps, but Esign was a really big part of the community, so with the help of Feather as the base app, I tried to recreate Esign as close as possible so you guys can easier to get familiar and less app switching for smooth sideloading.

Another reason is this app was built specifically for Khoindvn to share his certificates, allowing more people to access to sideloading without even have to buy a certificate!

## Help
You can create your Issue at [Issue](https://github.com/Nyasami/Ksign-public/issues), this will also be the place for you to request a new feature so feel free to make one!

You can also join Ksign Discord [here](https://discord.gg/sfbZfQzVdQ) for better communication.

## Download
Go to [Releases](https://github.com/Nyasami/Ksign-public/releases) and download the newest ipa from there.

## Star History

<a href="https://www.star-history.com/?repos=nyasami%2Fksign&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=nyasami/ksign&type=date&theme=dark&legend=top-left&sealed_token=qF8r8F35jlacPKoDFdro6gYpDDUbVGloo-UPsBBqrAufefIWUZ7MY_TmH4j_UB2ailJBO_OYzkYV-jye9GlGJR-PfMID-XHRW52SHl--bD976zJlaiDwOA" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=nyasami/ksign&type=date&legend=top-left&sealed_token=qF8r8F35jlacPKoDFdro6gYpDDUbVGloo-UPsBBqrAufefIWUZ7MY_TmH4j_UB2ailJBO_OYzkYV-jye9GlGJR-PfMID-XHRW52SHl--bD976zJlaiDwOA" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=nyasami/ksign&type=date&legend=top-left&sealed_token=qF8r8F35jlacPKoDFdro6gYpDDUbVGloo-UPsBBqrAufefIWUZ7MY_TmH4j_UB2ailJBO_OYzkYV-jye9GlGJR-PfMID-XHRW52SHl--bD976zJlaiDwOA" />
 </picture>
</a>

## Special thanks
- Feather by [claration](https://github.com/claration/Feather)  

- Product manager Khoindvn

- And you! for using the app ❤️

## Disclaimer

This project is maintained here, on GitHub. Releases are distributed here, on GitHub. We do not currently have a project website outside of this repository. Please make sure to avoid any sites that host our software as they are often malicious and are there to mislead to user.
