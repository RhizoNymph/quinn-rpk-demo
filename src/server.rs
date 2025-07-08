use anyhow::Result;
use hex::encode as hex_encode;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use quinn::crypto::rustls::QuicServerConfig;

use rustls::{
    pki_types::{CertificateDer, UnixTime},
    sign::{CertifiedKey},
    server::{ResolvesServerCert, ServerConfig, ClientHello, danger::{ClientCertVerified, ClientCertVerifier}},
    client::danger::HandshakeSignatureValid,
    SignatureScheme, Error, DistinguishedName, DigitallySignedStruct,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, path::Path};

use crate::common::make_rpk;

#[derive(Debug)]
struct OneRpk(Arc<CertifiedKey>);
impl ResolvesServerCert for OneRpk {
    fn resolve(
        &self,
        _client_hello: ClientHello,
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[derive(Debug)]
struct AcceptAnyClient;
impl ClientCertVerifier for AcceptAnyClient {
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer, _dss: &DigitallySignedStruct
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer, _dss: &DigitallySignedStruct
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519
        ]
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

pub async fn run_server(listen_addr: SocketAddr, key_path: Option<&Path>, cert_path: Option<&Path>) -> Result<()> {    
    let server_rpk = make_rpk(key_path, cert_path, "server.key", "server.crt")?;
    println!("server ‣ my id {}", hex_encode(Sha256::digest(&server_rpk.cert[0])));
    
    let tls = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyClient))
        .with_cert_resolver(Arc::new(OneRpk(server_rpk)));
    let crypto = QuicServerConfig::try_from(Arc::new(tls)).unwrap();
    let cfg = QuinnServerConfig::with_crypto(Arc::new(crypto));

    let endpoint = Endpoint::server(cfg, listen_addr)?;
    println!("server listening on {listen_addr}");

    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = connecting.await.expect("handshake failed");
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
