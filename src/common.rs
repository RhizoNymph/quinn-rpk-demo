use rcgen::KeyPair;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::{CertifiedKey, SigningKey},
    crypto::ring::sign::any_supported_type,
};
use std::sync::Arc;
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

pub fn make_rpk(
    key_path: Option<&Path>, 
    cert_path: Option<&Path>,
    default_key_path: &str,
    default_cert_path: &str
) -> Result<Arc<CertifiedKey>> {
    let key_file = key_path.unwrap_or(Path::new(default_key_path));
    let cert_file = cert_path.unwrap_or(Path::new(default_cert_path));
    
    // If both files exist and no explicit paths were provided, load from files
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
    
    // If explicit paths were provided, try to load from them
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
            return Err(anyhow::anyhow!(
                "Specified key or cert file does not exist: {} or {}", 
                key_file.display(), 
                cert_file.display()
            ));
        }
    }
    
    // Generate new RPK and save to files
    let kp = KeyPair::generate().context("Failed to generate keypair")?;
    let spki = CertificateDer::from(kp.public_key_der());
    let sk: Arc<dyn SigningKey> = any_supported_type(&PrivateKeyDer::Pkcs8(kp.serialize_der().into()))
        .context("Failed to create signing key")?;
    let rpk = Arc::new(CertifiedKey::new(vec![spki.clone()], sk));
    
    // Save to files (store DER format for simplicity)
    save_rpk_to_files(&kp, &spki, key_file, cert_file)?;
    println!("Generated and saved new RPK to {} and {}", key_file.display(), cert_file.display());
    
    Ok(rpk)
}

fn load_rpk_from_files(key_file: &Path, cert_file: &Path) -> Result<Arc<CertifiedKey>> {
    // Load DER-encoded private key
    let key_der = fs::read(key_file)
        .with_context(|| format!("Failed to read key file: {}", key_file.display()))?;
    
    // Load DER-encoded certificate
    let cert_der = fs::read(cert_file)
        .with_context(|| format!("Failed to read cert file: {}", cert_file.display()))?;
    
    let sk: Arc<dyn SigningKey> = any_supported_type(&PrivateKeyDer::Pkcs8(key_der.into()))
        .context("Failed to create signing key from loaded key")?;
    
    let cert = CertificateDer::from(cert_der);
    
    Ok(Arc::new(CertifiedKey::new(vec![cert], sk)))
}

fn save_rpk_to_files(kp: &KeyPair, cert: &CertificateDer, key_file: &Path, cert_file: &Path) -> Result<()> {
    // Save private key in DER format
    let key_der = kp.serialize_der();
    fs::write(key_file, key_der)
        .with_context(|| format!("Failed to write key file: {}", key_file.display()))?;
    
    // Save certificate in DER format
    fs::write(cert_file, cert.as_ref())
        .with_context(|| format!("Failed to write cert file: {}", cert_file.display()))?;
    
    Ok(())
}