use rcgen::KeyPair;
use rcgen::PKCS_ED25519;

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::{CertifiedKey, SigningKey},
    crypto::{ring::sign::any_eddsa_type, WebPkiSupportedAlgorithms},
    SignatureScheme,
};
use webpki::ring::ED25519;
use std::sync::Arc;
use std::fs;
use std::path::Path;
use anyhow::{anyhow, Result, Context};

pub static ED25519_ONLY: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ED25519],
    mapping: &[(SignatureScheme::ED25519, &[ED25519])]
};

pub fn make_rpk(
    key_path: Option<&Path>, 
    cert_path: Option<&Path>,
    default_key_path: &str,
    default_cert_path: &str
) -> Result<Arc<CertifiedKey>> {
    let key_file = key_path.unwrap_or(Path::new(default_key_path));
    let cert_file = cert_path.unwrap_or(Path::new(default_cert_path));
    
    if key_file.exists() && cert_file.exists() && key_path.is_none() && cert_path.is_none() {
        match load_rpk_from_files(key_file, cert_file) {
            Ok(rpk) => {
                println!("Loaded existing RPK from {} and {}", key_file.display(), cert_file.display());
                return Ok(rpk);
            }
            Err(e) => {
                println!("Failed to load existing RPK files: {}, generating new ones", e);
            }
        }
    }
    
    if key_path.is_some() || cert_path.is_some() {
        if key_file.exists() && cert_file.exists() {
            match load_rpk_from_files(key_file, cert_file) {
                Ok(rpk) => {
                    println!("Loaded RPK from {} and {}", key_file.display(), cert_file.display());
                    return Ok(rpk);
                }
                Err(e) => {
                    return Err(e).context("Failed to load RPK from specified files");
                }
            }
        } else {
            return Err(anyhow!(
                "Specified key or cert file does not exist: {} or {}", 
                key_file.display(), 
                cert_file.display()
            ));
        }
    }
    
    let kp = KeyPair::generate_for(&PKCS_ED25519).context("Failed to generate ED25519 keypair")?;
    let spki = CertificateDer::from(kp.public_key_der());
    let pkcs8_key = PrivatePkcs8KeyDer::from(kp.serialize_der());
    let sk: Arc<dyn SigningKey> = any_eddsa_type(&pkcs8_key)
        .context("Failed to create signing key")?;
    let rpk = Arc::new(CertifiedKey::new(vec![spki.clone()], sk));
    
    save_rpk_to_files(&kp, &spki, key_file, cert_file)?;
    println!("Generated and saved new ED25519 RPK to {} and {}", key_file.display(), cert_file.display());
    
    Ok(rpk)
}

fn load_rpk_from_files(key_file: &Path, cert_file: &Path) -> Result<Arc<CertifiedKey>> {
    let key_der = fs::read(key_file)
        .with_context(|| format!("Failed to read key file: {}", key_file.display()))?;
    
    let cert_der = fs::read(cert_file)
        .with_context(|| format!("Failed to read cert file: {}", cert_file.display()))?;
        
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let pkcs8_key = match private_key {
        PrivateKeyDer::Pkcs8(pkcs8) => pkcs8,
        _ => return Err(anyhow!("Ed25519 keys must be in PKCS8 format")),
    };
    
    let sk: Arc<dyn SigningKey> = any_eddsa_type(&pkcs8_key)
        .context("Failed to create signing key from loaded key")?;
    
    let cert = CertificateDer::from(cert_der);
    
    Ok(Arc::new(CertifiedKey::new(vec![cert], sk)))
}

fn save_rpk_to_files(kp: &KeyPair, cert: &CertificateDer, key_file: &Path, cert_file: &Path) -> Result<()> {
    let key_der = kp.serialize_der();
    fs::write(key_file, key_der)
        .with_context(|| format!("Failed to write key file: {}", key_file.display()))?;
        
    fs::write(cert_file, cert.as_ref())
        .with_context(|| format!("Failed to write cert file: {}", cert_file.display()))?;
    
    Ok(())
}