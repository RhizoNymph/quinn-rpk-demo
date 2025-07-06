use anyhow::Result;
use hex::encode as hex_encode;
use quinn::{Endpoint};
use quinn::crypto::rustls::QuicClientConfig;
use rcgen::KeyPair;
use rustls::{
    client::danger::{ServerCertVerified, ServerCertVerifier},
    crypto::ring::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::{CertifiedKey, SigningKey},
    ClientConfig,
};
use rustls::SignatureScheme;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/* ---------- helper to build our own RPK (only needed for mutual auth) ---------- */
fn make_rpk() -> Arc<CertifiedKey> {
    let kp = KeyPair::generate().unwrap();
    let spki = CertificateDer::from(kp.public_key_der());
    let sk: Arc<dyn SigningKey> =
        any_supported_type(&PrivateKeyDer::Pkcs8(kp.serialize_der().into())).unwrap();
    Arc::new(CertifiedKey::new(vec![spki], sk))
}

#[tokio::main]
async fn main() -> Result<()> {
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    /* rustls client: trust ANY RPK (AcceptAny) */
    let tls = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();                       // not sending a client key

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
    send.write_all(b"hello raw-key quic").await?;
    send.finish().unwrap();
    let echoed = recv.read_to_end(usize::MAX).await?;
    println!("client ‣ echoed: {}", String::from_utf8_lossy(&echoed));
    Ok(())
}
