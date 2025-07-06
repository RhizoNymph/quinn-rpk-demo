use anyhow::Result;
use hex::encode as hex_encode;
use quinn::{Endpoint, Incoming};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::KeyPair;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::{CertifiedKey, SigningKey},
    crypto::ring::sign::any_supported_type,
    server::{ResolvesServerCert, ServerConfig},
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/* ---------- helper: build a single Raw-Public-Key CertifiedKey ---------- */
fn make_rpk() -> Arc<CertifiedKey> {
    let kp = KeyPair::generate().unwrap();                      // Ed25519
    let spki = CertificateDer::from(kp.public_key_der());
    let sk: Arc<dyn SigningKey> =
        any_supported_type(&PrivateKeyDer::Pkcs8(kp.serialize_der().into())).unwrap();
    Arc::new(CertifiedKey::new(vec![spki], sk))
}

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

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:4433".parse()?;

    /* rustls → quinn config */
    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneRpk(make_rpk())));
    let crypto = QuicServerConfig::try_from(Arc::new(tls)).unwrap();
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    /* bind endpoint */
    let endpoint = Endpoint::server(cfg, addr)?;
    println!("server listening on {addr}");

    /* accept loop */
    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = connecting.await.expect("handshake failed");
            /* peer-id = SHA-256(SPKI) */
            if let Some(arc_any) = conn.peer_identity() {
                if let Some(certs) = arc_any.downcast_ref::<Vec<CertificateDer>>() {
                    println!("client id {}", hex_encode(Sha256::digest(certs[0].as_ref())));
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
