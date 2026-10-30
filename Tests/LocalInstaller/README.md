# LocalInstaller tests (macOS)

Tests the real `Ksign/Backend/Server/IPAResponder.swift` (symlinked, not copied) against a real
Vapor server: range parsing, 200/206/416, 250 MB / 500 MB streaming with memory sampling,
interrupted transfers (fd leak check), and real TLS handshakes using the PKI from
`Scripts/make-local-pki.sh` (curl/openssl with strict verification).

    cd Tests/LocalInstaller
    swift test                      # runs everything (needs curl, openssl, network for first build)
    KSIGN_SKIP_LARGE=1 swift test   # skip the 250/500 MB tests
