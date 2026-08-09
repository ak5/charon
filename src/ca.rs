//! Operator-owned deployment CA lifecycle helpers.

use std::{fs::OpenOptions, io::Write as _, path::Path};

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use sha2::{Digest as _, Sha256};

use crate::{config::TlsConfig, tls::TlsAuthority};

/// Generate a new self-signed deployment CA without overwriting files.
///
/// # Errors
///
/// Returns an error if either target exists or secure creation fails.
pub fn generate(name: &str, certificate: &Path, private_key: &Path) -> Result<()> {
    if name.is_empty() || name.len() > 128 || name.contains(['\r', '\n']) {
        bail!("CA name is invalid");
    }
    let key = KeyPair::generate().context("failed to generate CA key")?;
    let key_pem = key.serialize_pem();
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, name);
    params.distinguished_name = distinguished_name;
    let issuer = CertifiedIssuer::self_signed(params, key).context("failed to sign CA")?;
    write_new(private_key, key_pem.as_bytes(), true)?;
    if let Err(error) = write_new(certificate, issuer.pem().as_bytes(), false) {
        let _ = std::fs::remove_file(private_key);
        return Err(error);
    }
    Ok(())
}

/// Validate that a certificate and protected private key form a usable CA.
///
/// # Errors
///
/// Returns an error for invalid, mismatched, or unsafe key material.
pub fn validate(certificate: &Path, private_key: &Path) -> Result<String> {
    let config = TlsConfig {
        ca_certificate: certificate.to_owned(),
        ca_private_key: private_key.to_owned(),
    };
    let _ = TlsAuthority::load(&config)?;
    fingerprint(certificate)
}

/// Return the SHA-256 fingerprint of the public certificate DER.
///
/// # Errors
///
/// Returns an error when the certificate cannot be parsed.
pub fn fingerprint(certificate: &Path) -> Result<String> {
    let pem = std::fs::read(certificate).context("failed to read CA certificate")?;
    let der = CertificateDer::from_pem_slice(&pem).context("CA certificate PEM is invalid")?;
    let digest = Sha256::digest(der.as_ref());
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Export a public CA certificate without touching its private key.
///
/// # Errors
///
/// Refuses to overwrite an existing target.
pub fn export(certificate: &Path, output: &Path) -> Result<()> {
    let pem = std::fs::read(certificate).context("failed to read CA certificate")?;
    let _ = CertificateDer::from_pem_slice(&pem).context("CA certificate PEM is invalid")?;
    write_new(output, &pem, false)
}

fn write_new(path: &Path, value: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(value)
        .context("failed to write CA material")?;
    file.sync_all().context("failed to sync CA material")
}

#[cfg(test)]
mod tests {
    use super::{export, fingerprint, generate, validate};

    #[test]
    fn generates_validates_and_exports_without_overwrite() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let certificate = directory.path().join("ca.pem");
        let private_key = directory.path().join("ca-key.pem");
        let exported = directory.path().join("public.pem");
        generate("Charon fixture CA", &certificate, &private_key)
            .unwrap_or_else(|error| panic!("{error}"));
        let expected = fingerprint(&certificate).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            validate(&certificate, &private_key).unwrap_or_else(|error| panic!("{error}")),
            expected
        );
        export(&certificate, &exported).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            std::fs::read(certificate).unwrap_or_else(|error| panic!("{error}")),
            std::fs::read(&exported).unwrap_or_else(|error| panic!("{error}"))
        );
        assert!(generate("again", &exported, &private_key).is_err());
    }
}
