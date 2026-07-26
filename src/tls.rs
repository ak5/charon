//! Charon-owned certificate authority for per-host CONNECT interception.

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject as _},
};
use secrecy::{ExposeSecret as _, SecretString};

use crate::config::TlsConfig;

/// CA signer that intentionally has no `Debug`, serialization, or response
/// conversion implementation.
pub struct TlsAuthority {
    certificate_pem: String,
    certificate_der: CertificateDer<'static>,
    private_key: KeyPair,
}

impl TlsAuthority {
    /// Load the public CA and protected signer from exact configured paths.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, over-permissive, or malformed CA material.
    pub fn load(config: &TlsConfig) -> Result<Self> {
        ensure_private_permissions(&config.ca_private_key)?;
        let certificate_pem = std::fs::read_to_string(&config.ca_certificate)
            .context("failed to read TLS CA certificate")?;
        let private_pem = SecretString::from(
            std::fs::read_to_string(&config.ca_private_key)
                .context("failed to read TLS CA private key")?,
        );
        let private_key = KeyPair::from_pem(private_pem.expose_secret())
            .context("TLS CA private key is invalid")?;
        Issuer::from_ca_cert_pem(&certificate_pem, &private_key)
            .context("TLS CA certificate is invalid or does not match its key")?;
        let certificate_der = CertificateDer::from_pem_slice(certificate_pem.as_bytes())
            .context("TLS CA certificate PEM is invalid")?;
        Ok(Self {
            certificate_pem,
            certificate_der,
            private_key,
        })
    }

    /// Issue an ephemeral server configuration for one exact DNS hostname.
    ///
    /// # Errors
    ///
    /// Returns an error if leaf creation or TLS configuration fails.
    pub fn server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        if hostname.is_empty() || hostname.contains('*') {
            bail!("TLS leaf hostname is invalid");
        }
        let issuer = Issuer::from_ca_cert_pem(&self.certificate_pem, &self.private_key)
            .context("TLS CA certificate became invalid")?;
        let leaf_key = KeyPair::generate().context("failed to generate TLS leaf key")?;
        let leaf = CertificateParams::new(vec![hostname.to_owned()])
            .context("TLS leaf hostname is invalid")?
            .signed_by(&leaf_key, &issuer)
            .context("failed to sign TLS leaf certificate")?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .context("failed to select safe TLS protocol versions")?
                .with_no_client_auth()
                .with_single_cert(
                    vec![
                        CertificateDer::from(leaf.der().to_vec()),
                        self.certificate_der.clone(),
                    ],
                    private_key,
                )
                .context("failed to configure TLS leaf certificate")?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

#[cfg(unix)]
fn ensure_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::metadata(path)
        .context("failed to inspect TLS CA private key")?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!("TLS CA private key must not be accessible by group or other");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_permissions(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("TLS CA private key is unavailable");
    }
    Ok(())
}
