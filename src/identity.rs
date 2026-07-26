//! Replay-resistant signed workload identity and capability authorization.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use http::Method;
use serde::{Deserialize, Serialize};

use crate::config::{CapabilityPolicy, Config};

/// Header carrying the signed workload manifest.
pub const IDENTITY_HEADER: &str = "proxy-authorization";

/// Claims signed by the workload-identity issuer.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadClaims {
    /// Exact configured issuer.
    pub iss: String,
    /// Exact Charon audience.
    pub aud: String,
    /// Stable workload identifier.
    pub sub: String,
    /// Stable tenant owning the workload.
    pub tenant: String,
    /// Persona bound by the issuer.
    pub persona: String,
    /// Stable workspace identifier.
    pub workspace: String,
    /// Active workspace lease identifier.
    pub lease: String,
    /// Redacted cross-system operation correlation identifier.
    pub operation: String,
    /// Named configured capability.
    pub capability: String,
    /// Single-use unpredictable identifier.
    pub jti: String,
    /// Issued-at Unix timestamp.
    pub iat: u64,
    /// Not-before Unix timestamp.
    pub nbf: u64,
    /// Expiry Unix timestamp.
    pub exp: u64,
}

/// Authorized identity fields safe for audit correlation.
#[derive(Clone, Debug)]
pub struct AuthorizedWorkload {
    /// Stable workload identifier.
    pub workload: String,
    /// Authorized tenant.
    pub tenant: String,
    /// Authorized persona.
    pub persona: String,
    /// Authorized workspace.
    pub workspace: String,
    /// Authorized active lease.
    pub lease: String,
    /// Authorized operation correlation identifier.
    pub operation: String,
    /// Authorized capability name.
    pub capability: String,
}

/// Verifies signatures, validity windows, capabilities, and single-use nonces.
pub struct IdentityVerifier {
    key: VerifyingKey,
    issuer: String,
    audience: String,
    max_ttl_seconds: u64,
    clock_skew_seconds: u64,
    used_nonces: Mutex<HashMap<String, u64>>,
}

impl IdentityVerifier {
    /// Build a verifier from validated configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the public key is malformed.
    pub fn new(config: &Config) -> Result<Self> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&config.identity.public_key)
            .context("identity public_key is not valid base64")?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("identity public_key must contain 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes).context("identity public_key is invalid")?;
        Ok(Self {
            key,
            issuer: config.identity.issuer.clone(),
            audience: config.identity.audience.clone(),
            max_ttl_seconds: config.identity.max_ttl_seconds,
            clock_skew_seconds: config.identity.clock_skew_seconds,
            used_nonces: Mutex::new(HashMap::new()),
        })
    }

    /// Authenticate and authorize one request, consuming its nonce.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or invalid manifests, time violations,
    /// unknown capabilities, operation mismatch, and nonce replay.
    pub fn authorize(
        &self,
        token: &str,
        config: &Config,
        service: &str,
        method: &Method,
        path: &str,
    ) -> Result<AuthorizedWorkload> {
        self.authorize_at(token, config, service, method, path, unix_now()?)
    }

    fn authorize_at(
        &self,
        token: &str,
        config: &Config,
        service: &str,
        method: &Method,
        path: &str,
        now: u64,
    ) -> Result<AuthorizedWorkload> {
        let claims = self.verify(token)?;
        if claims.iss != self.issuer || claims.aud != self.audience {
            bail!("workload identity issuer or audience is not authorized");
        }
        if [
            claims.sub.as_str(),
            claims.tenant.as_str(),
            claims.persona.as_str(),
            claims.workspace.as_str(),
            claims.lease.as_str(),
            claims.operation.as_str(),
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 128)
            || claims.jti.len() < 16
        {
            bail!("workload identity fields are invalid");
        }
        if claims.tenant != config.realm.tenant || claims.persona != config.realm.persona {
            bail!("workload identity is assigned to another realm");
        }
        if claims.exp <= claims.iat
            || claims.nbf > claims.exp
            || claims.exp - claims.iat > self.max_ttl_seconds
        {
            bail!("workload identity lifetime is invalid");
        }
        let skew = self.clock_skew_seconds;
        if claims.iat > now.saturating_add(skew)
            || claims.nbf > now.saturating_add(skew)
            || claims.exp.saturating_add(skew) < now
        {
            bail!("workload identity is outside its validity window");
        }
        let capability = config
            .capability(&claims.capability)
            .context("workload capability is not configured")?;
        authorize_operation(capability, &claims, service, method, path)?;
        self.consume_nonce(&claims.jti, claims.exp, now)?;
        Ok(AuthorizedWorkload {
            workload: claims.sub,
            tenant: claims.tenant,
            persona: claims.persona,
            workspace: claims.workspace,
            lease: claims.lease,
            operation: claims.operation,
            capability: claims.capability,
        })
    }

    fn verify(&self, token: &str) -> Result<WorkloadClaims> {
        let (payload, signature) = token
            .split_once('.')
            .context("workload identity is malformed")?;
        if signature.contains('.') {
            bail!("workload identity is malformed");
        }
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .context("workload identity payload is malformed")?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature)
            .context("workload identity signature is malformed")?;
        let signature = Signature::from_slice(&signature_bytes)
            .context("workload identity signature has invalid length")?;
        self.key
            .verify(payload.as_bytes(), &signature)
            .context("workload identity signature is invalid")?;
        serde_json::from_slice(&payload_bytes).context("workload identity claims are invalid")
    }

    fn consume_nonce(&self, nonce: &str, expires: u64, now: u64) -> Result<()> {
        let mut used = self
            .used_nonces
            .lock()
            .map_err(|_| anyhow::anyhow!("workload replay cache is unavailable"))?;
        used.retain(|_, expiry| expiry.saturating_add(self.clock_skew_seconds) >= now);
        if used.insert(nonce.to_owned(), expires).is_some() {
            bail!("workload identity nonce was already used");
        }
        Ok(())
    }
}

fn authorize_operation(
    capability: &CapabilityPolicy,
    claims: &WorkloadClaims,
    service: &str,
    method: &Method,
    path: &str,
) -> Result<()> {
    if capability.persona != claims.persona || capability.service != service {
        bail!("workload identity is not bound to this persona or service");
    }
    if !capability
        .methods
        .iter()
        .any(|item| item == method.as_str())
        || !capability.paths.iter().any(|item| item == path)
    {
        bail!("workload capability does not authorize this operation");
    }
    Ok(())
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::{IdentityVerifier, WorkloadClaims};
    use crate::config::{
        CapabilityPolicy, Config, IdentityConfig, ProviderConfig, RealmConfig, ServicePolicy,
    };

    const NOW: u64 = 1_800_000_000;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9_u8; 32])
    }

    fn config() -> Config {
        Config {
            realm: RealmConfig {
                id: "realm-alice".into(),
                tenant: "tenant-one".into(),
                persona: "alice".into(),
                generation: 1,
            },
            listen: "127.0.0.1:3129"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            upstream_proxy: None,
            provider: ProviderConfig::Environment,
            tls: None,
            identity: IdentityConfig {
                issuer: "test-issuer".into(),
                audience: "charon".into(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(signing_key().verifying_key().to_bytes()),
                max_ttl_seconds: 60,
                clock_skew_seconds: 2,
            },
            capabilities: vec![CapabilityPolicy {
                name: "github-user".into(),
                persona: "alice".into(),
                service: "github".into(),
                methods: vec!["GET".into()],
                paths: vec!["/user".into()],
            }],
            services: vec![ServicePolicy {
                name: "github".into(),
                hosts: vec!["api.github.com".into()],
                header: "authorization".into(),
                placeholder: "Bearer placeholder".into(),
                value_template: "Bearer {secret}".into(),
                secret_ref: "github/alice".into(),
            }],
        }
    }

    fn claims() -> WorkloadClaims {
        WorkloadClaims {
            iss: "test-issuer".into(),
            aud: "charon".into(),
            sub: "workload-123".into(),
            tenant: "tenant-one".into(),
            persona: "alice".into(),
            workspace: "workspace-one".into(),
            lease: "lease-one".into(),
            operation: "operation-one".into(),
            capability: "github-user".into(),
            jti: "nonce-1234567890".into(),
            iat: NOW - 1,
            nbf: NOW - 1,
            exp: NOW + 30,
        }
    }

    fn sign(claims: &WorkloadClaims) -> String {
        let payload = serde_json::to_vec(claims).unwrap_or_else(|error| panic!("{error}"));
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let signature = signing_key().sign(encoded.as_bytes());
        format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn authorize(verifier: &IdentityVerifier, token: &str, config: &Config) -> anyhow::Result<()> {
        verifier
            .authorize_at(token, config, "github", &http::Method::GET, "/user", NOW)
            .map(|_| ())
    }

    #[test]
    fn accepts_a_valid_single_use_manifest() {
        let config = config();
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(authorize(&verifier, &sign(&claims()), &config).is_ok());
    }

    #[test]
    fn rejects_expired_wrong_audience_replay_and_cross_persona() {
        let config = config();

        let mut expired = claims();
        expired.iat = NOW - 40;
        expired.nbf = NOW - 40;
        expired.exp = NOW - 10;
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(authorize(&verifier, &sign(&expired), &config).is_err());

        let mut wrong_audience = claims();
        wrong_audience.aud = "another-service".into();
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(authorize(&verifier, &sign(&wrong_audience), &config).is_err());

        let token = sign(&claims());
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(authorize(&verifier, &token, &config).is_ok());
        assert!(authorize(&verifier, &token, &config).is_err());

        let mut cross_persona = claims();
        cross_persona.persona = "bob".into();
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(authorize(&verifier, &sign(&cross_persona), &config).is_err());

        let mut cross_tenant = claims();
        cross_tenant.tenant = "tenant-two".into();
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(authorize(&verifier, &sign(&cross_tenant), &config).is_err());
    }

    #[test]
    fn rejects_tampering_and_operation_mismatch() {
        let config = config();
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        let mut token = sign(&claims()).into_bytes();
        token[0] = if token[0] == b'A' { b'B' } else { b'A' };
        let token = String::from_utf8(token).unwrap_or_else(|error| panic!("{error}"));
        assert!(authorize(&verifier, &token, &config).is_err());

        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            verifier
                .authorize_at(
                    &sign(&claims()),
                    &config,
                    "github",
                    &http::Method::POST,
                    "/user",
                    NOW,
                )
                .is_err()
        );

        let mut different_path = claims();
        different_path.jti = "nonce-different-path".into();
        let verifier = IdentityVerifier::new(&config).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            verifier
                .authorize_at(
                    &sign(&different_path),
                    &config,
                    "github",
                    &http::Method::GET,
                    "/repos",
                    NOW,
                )
                .is_err()
        );
    }
}
