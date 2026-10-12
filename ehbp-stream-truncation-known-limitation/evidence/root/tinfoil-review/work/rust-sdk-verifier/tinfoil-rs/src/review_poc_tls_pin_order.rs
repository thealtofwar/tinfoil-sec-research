//! REVIEW negative control (not in upstream): does the pinned TLS client ever
//! send application bytes (the HTTP request with its Authorization header) to
//! a peer whose certificate fails the WebPKI chain or the SPKI pin?
//!
//! A loopback rustls server with a self-signed P-256 certificate records
//! whether the handshake completed and how many application bytes arrived.

#[cfg(test)]
mod tests {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs;
    use std::io::Write as _;
    use std::process::Command;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    const EVIDENCE: &str =
        "/root/tinfoil-review/work/rust-sdk-verifier/results/tls_pin_order_evidence.txt";

    fn log(line: &str) {
        println!("{line}");
        let _ = fs::create_dir_all("/root/tinfoil-review/work/rust-sdk-verifier/results");
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(EVIDENCE) {
            let _ = writeln!(f, "{line}");
        }
    }

    fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let dir = std::env::temp_dir().join(format!("tinfoil-review-tls-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let key = dir.join("key.pem");
        let cert = dir.join("cert.pem");
        let status = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", key.to_str().unwrap(), "-out", cert.to_str().unwrap(),
                "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1",
            ])
            .output()
            .expect("openssl available");
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        let cert_der = pem::parse(fs::read(&cert).unwrap()).unwrap().into_contents();
        let key_der = pem::parse(fs::read(&key).unwrap()).unwrap().into_contents();
        (
            CertificateDer::from(cert_der),
            PrivateKeyDer::Pkcs8(key_der.into()),
        )
    }

    async fn run_case(label: &str, pinned_fingerprint: &str) {
        let (cert, key) = self_signed();
        let actual_fp = crate::verifier::tls::cert_pubkey_fingerprint(&cert).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let mut buf = Vec::new();
                    let _ = tls.read_to_end(&mut buf).await;
                    (true, buf)
                }
                Err(e) => (false, e.to_string().into_bytes()),
            }
        });

        let pinned = crate::verifier::tls::create_host_bound_pinned_client(
            pinned_fingerprint,
            reqwest::Url::parse(&format!("https://127.0.0.1:{}", addr.port())).unwrap(),
        )
        .unwrap();
        let result = pinned
            .exposed
            .get(format!("https://127.0.0.1:{}/v1/models", addr.port()))
            .bearer_auth("tinfoil-api-key-SECRET")
            .send()
            .await;
        let (handshake_ok, bytes) = server.await.unwrap();
        log(&format!(
            "[{label}] pin={} actual_spki={} client_result={} server_handshake_completed={} app_bytes_received={} ({})",
            &pinned_fingerprint[..16],
            &actual_fp[..16],
            match &result {
                Ok(r) => format!("Ok(status {})", r.status()),
                Err(e) => format!("Err({})", e.to_string().replace('\n', " ")),
            },
            handshake_ok,
            if handshake_ok { bytes.len() } else { 0 },
            if handshake_ok {
                String::from_utf8_lossy(&bytes).chars().take(80).collect::<String>()
            } else {
                format!("server error: {}", String::from_utf8_lossy(&bytes))
            }
        ));
        assert!(result.is_err());
        assert!(!handshake_ok, "handshake must fail before any application data");
    }

    #[tokio::test]
    async fn pinned_client_sends_no_application_bytes_when_chain_or_pin_fails() {
        // Case A: correct SPKI pin but a self-signed (non-WebPKI) certificate:
        // PinnedCertVerifier runs the WebPKI check first and aborts the handshake.
        let (cert, _) = self_signed();
        let fp = crate::verifier::tls::cert_pubkey_fingerprint(&cert).unwrap();
        run_case("correct pin, untrusted chain", &fp).await;
        // Case B: wrong pin.
        run_case("wrong pin, untrusted chain", &"0".repeat(64)).await;
    }
}
