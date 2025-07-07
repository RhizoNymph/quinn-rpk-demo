use anyhow::Result;
use hex::encode as hex_encode;
use quinn::{Endpoint};
use quinn::crypto::rustls::QuicClientConfig;

use rustls::{
    client::danger::{ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer},
    sign::{CertifiedKey},
    ClientConfig,
};
use rustls::SignatureScheme;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use std::path::Path;

use crate::common::make_rpk;

/* ---------- accept-all RPK verifier ---------- */
#[derive(Debug)]
struct AcceptAny;
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _ee: &CertificateDer,
        _ints: &[CertificateDer],
        _name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _m: &[u8], _c: &CertificateDer, _d: &rustls::DigitallySignedStruct
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _m: &[u8], _c: &CertificateDer, _d: &rustls::DigitallySignedStruct
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,     // ← key one!
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

/* ---------- trivial resolver that always returns our client key ---------- */
#[derive(Debug)]
struct OneRpk(Arc<CertifiedKey>);
impl rustls::client::ResolvesClientCert for OneRpk {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}

pub async fn run_client(server_addr: SocketAddr, key_path: Option<&Path>, cert_path: Option<&Path>) -> Result<()> {
    // Generate our client RPK
    let client_rpk = make_rpk(key_path, cert_path, "client.key", "client.crt")?;
    println!("client ‣ my id {}", hex_encode(Sha256::digest(&client_rpk.cert[0])));

    /* rustls client: trust ANY RPK (AcceptAny) and send our own RPK */
    let tls = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_client_cert_resolver(Arc::new(OneRpk(client_rpk)));

    let crypto = QuicClientConfig::try_from(Arc::new(tls))?;
    let cfg = quinn::ClientConfig::new(Arc::new(crypto));

    let mut ep = Endpoint::client("[::]:0".parse()?)?;
    ep.set_default_client_config(cfg);

    let conn = ep.connect(server_addr, "ignored.sni")?.await?;
    if let Some(arc_any) = conn.peer_identity() {
        if let Some(certs) = arc_any.downcast_ref::<Vec<CertificateDer>>() {
            println!(
                "client ‣ server id {}",
                hex_encode(Sha256::digest(certs[0].as_ref()))
            );
        }
    }

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello mutual rpk quic").await?;
    send.finish().unwrap();
    let echoed = recv.read_to_end(usize::MAX).await?;
    println!("client ‣ echoed: {}", String::from_utf8_lossy(&echoed));
    Ok(())
}
