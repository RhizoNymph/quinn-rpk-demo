use anyhow::Result;
use hex::encode as hex_encode;
use quinn::Endpoint;
use quinn::crypto::rustls::QuicServerConfig;

use rustls::{
    pki_types::{CertificateDer},
    sign::{CertifiedKey},
    server::{ResolvesServerCert, ServerConfig, danger::{ClientCertVerified, ClientCertVerifier}},
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, path::Path};

use crate::common::make_rpk;

/* ---------- trivial resolver that always returns that key ---------- */
#[derive(Debug)]
struct OneRpk(Arc<CertifiedKey>);
impl ResolvesServerCert for OneRpk {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/* ---------- accept-all client RPK verifier ---------- */
#[derive(Debug)]
struct AcceptAnyClient;
impl ClientCertVerifier for AcceptAnyClient {
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer, _dss: &rustls::DigitallySignedStruct
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer, _dss: &rustls::DigitallySignedStruct
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

pub async fn run_server(listen_addr: SocketAddr, key_path: Option<&Path>, cert_path: Option<&Path>) -> Result<()> {
    // Generate our server RPK
    let server_rpk = make_rpk(key_path, cert_path, "server.key", "server.crt")?;
    println!("server ‣ my id {}", hex_encode(Sha256::digest(&server_rpk.cert[0])));

    /* rustls → quinn config */
    let tls = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyClient))
        .with_cert_resolver(Arc::new(OneRpk(server_rpk)));
    let crypto = QuicServerConfig::try_from(Arc::new(tls)).unwrap();
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    /* bind endpoint */
    let endpoint = Endpoint::server(cfg, listen_addr)?;
    println!("server listening on {listen_addr}");

    /* accept loop */
    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = connecting.await.expect("handshake failed");
            /* peer-id = SHA-256(SPKI) */
            if let Some(arc_any) = conn.peer_identity() {
                if let Some(certs) = arc_any.downcast_ref::<Vec<CertificateDer>>() {
                    println!("server ‣ client id {}", hex_encode(Sha256::digest(certs[0].as_ref())));
                }
            }

            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let data = recv.read_to_end(usize::MAX).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.finish().unwrap();
            }
        });
    }
    Ok(())
}
