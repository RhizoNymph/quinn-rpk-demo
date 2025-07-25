use anyhow::Result;
use hex::encode as hex_encode;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};

use rustls::crypto::verify_tls13_signature_with_raw_key;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::{
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        AlwaysResolvesServerRawPublicKeys, ServerConfig,
    },
    DigitallySignedStruct, DistinguishedName, Error,
    Error::PeerIncompatible as PeerIncompatibleError,
    PeerIncompatible, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::Path, sync::Arc};

use crate::common::{make_rpk, ED25519_ONLY};

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
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(PeerIncompatibleError(
            PeerIncompatible::Tls13RequiredForQuic,
        ))
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(
            _message,
            &SubjectPublicKeyInfoDer::from(_cert.as_ref()),
            _dss,
            &ED25519_ONLY,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

pub async fn run_server(
    listen_addr: SocketAddr,
    key_path: Option<&Path>,
    cert_path: Option<&Path>,
) -> Result<()> {
    let server_rpk = make_rpk(key_path, cert_path, "server.key", "server.crt")?;
    println!(
        "server ‣ my id {}",
        hex_encode(Sha256::digest(&server_rpk.cert[0]))
    );

    let tls = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyClient))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(server_rpk)));
    let crypto = QuicServerConfig::try_from(Arc::new(tls)).unwrap();
    let cfg = QuinnServerConfig::with_crypto(Arc::new(crypto));

    let endpoint = Endpoint::server(cfg, listen_addr)?;
    println!("server listening on {listen_addr}");

    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = connecting.await.expect("handshake failed");
            if let Some(arc_any) = conn.peer_identity() {
                if let Some(certs) = arc_any.downcast_ref::<Vec<CertificateDer>>() {
                    println!(
                        "server ‣ client id {}",
                        hex_encode(Sha256::digest(certs[0].as_ref()))
                    );
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
