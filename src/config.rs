//! Fail-closed policy configuration.

use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde::Deserialize;

/// Process configuration loaded from a TOML file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Stable ownership boundary for this single-persona process.
    pub realm: RealmConfig,
    /// Address exposed by the Charon process.
    pub listen: SocketAddr,
    /// Optional upstream proxy and protected authentication input.
    pub upstream_proxy: Option<UpstreamProxyConfig>,
    /// Credential-provider implementation and its narrowly scoped inputs.
    pub provider: ProviderConfig,
    /// Optional Charon-owned interception CA used only for HTTPS CONNECT.
    pub tls: Option<TlsConfig>,
    /// Signed workload-manifest verification policy.
    pub identity: IdentityConfig,
    /// Named capabilities that bind a persona to one service and operation set.
    pub capabilities: Vec<CapabilityPolicy>,
    /// Explicit credential-injection allowlist.
    pub services: Vec<ServicePolicy>,
}

/// Stable orchestrator-neutral ownership bound to one isolated Charon process.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmConfig {
    /// Opaque stable infrastructure realm identifier.
    pub id: String,
    /// Stable tenant identifier assigned by the integrating control plane.
    pub tenant: String,
    /// Stable persona identifier assigned by the integrating control plane.
    pub persona: String,
    /// Declarative configuration generation reported in audit events.
    pub generation: u64,
}

/// Charon-owned upstream proxy route and optional file-backed Basic auth.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProxyConfig {
    /// Exact proxy URL without embedded credentials.
    pub url: String,
    /// Fixed Basic-auth username, required with `password_file`.
    pub username: Option<String>,
    /// Absolute protected file containing only the Basic-auth password.
    pub password_file: Option<PathBuf>,
}

/// Files containing the public interception CA and its protected signing key.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Absolute path to the PEM-encoded CA certificate.
    pub ca_certificate: std::path::PathBuf,
    /// Absolute path to the PEM-encoded CA private key.
    pub ca_private_key: std::path::PathBuf,
}

/// Credential-provider selection.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderConfig {
    /// Prototype environment provider for disposable development credentials.
    Environment,
    /// Vaultwarden access through the official Bitwarden CLI compatibility API.
    Vaultwarden(VaultwardenConfig),
}

/// Locked-by-default Vaultwarden provider configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultwardenConfig {
    /// Absolute path to the pinned `bw` CLI executable.
    pub cli_path: std::path::PathBuf,
    /// Dedicated directory containing only the encrypted CLI vault state.
    pub appdata_dir: std::path::PathBuf,
    /// Root-readable file containing a short-lived unlock session.
    pub session_file: std::path::PathBuf,
    /// Maximum in-memory lifetime of resolved values.
    pub cache_ttl_seconds: u64,
    /// Explicit opaque-reference to vault-item mapping.
    pub items: Vec<VaultItemMapping>,
}

/// One exact Charon reference mapped to one exact Vaultwarden item UUID.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultItemMapping {
    /// Opaque reference used by service policy.
    pub secret_ref: String,
    /// Exact persona allowed to use the mapped item.
    pub persona: String,
    /// Exact Vaultwarden item UUID read with `bw get password`.
    pub item_id: String,
}

/// Verification parameters for short-lived workload manifests.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Exact trusted issuer identifier.
    pub issuer: String,
    /// Exact Charon audience identifier.
    pub audience: String,
    /// Base64-encoded Ed25519 public verification key.
    pub public_key: String,
    /// Maximum accepted lifetime of a manifest.
    pub max_ttl_seconds: u64,
    /// Allowed clock skew for `iat`, `nbf`, and `exp` checks.
    pub clock_skew_seconds: u64,
}

/// One caller-independent operation grant.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicy {
    /// Stable capability identifier carried by signed manifests.
    pub name: String,
    /// Exact persona allowed to exercise the capability.
    pub persona: String,
    /// Exact configured service name.
    pub service: String,
    /// Exact allowed HTTP methods.
    pub methods: Vec<String>,
    /// Exact allowed request paths.
    pub paths: Vec<String>,
}

/// One downstream service and the only credential transformation allowed for it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicy {
    /// Stable service name used in policy and audit events.
    pub name: String,
    /// Exact destination hostnames. Wildcards are intentionally unsupported.
    pub hosts: Vec<String>,
    /// Request header whose placeholder may be replaced.
    pub header: String,
    /// Exact value the untrusted workload must send.
    pub placeholder: String,
    /// Rendered upstream value. Exactly one `{secret}` marker is required.
    pub value_template: String,
    /// Credential provider key. The prototype environment provider treats this
    /// as an environment-variable name in the Charon process only.
    pub secret_ref: String,
}

impl Config {
    /// Load and validate configuration from disk.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, TOML parsing fails, or
    /// the resulting policy violates a fail-closed invariant.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: Self =
            toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Reject ambiguous or unsafe configuration before opening a listener.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, duplicate, wildcard, or otherwise ambiguous
    /// policy declarations.
    pub fn validate(&self) -> Result<()> {
        self.validate_realm()?;
        self.validate_identity()?;
        self.validate_upstream_proxy()?;
        if let Some(tls) = &self.tls
            && (!tls.ca_certificate.is_absolute() || !tls.ca_private_key.is_absolute())
        {
            bail!("TLS CA certificate and key paths must be absolute");
        }
        if self.services.is_empty() {
            bail!("at least one service policy is required");
        }
        if self.capabilities.is_empty() {
            bail!("at least one capability policy is required");
        }
        let vault_refs = self.validate_provider()?;

        let mut names = HashSet::new();
        let mut hosts = HashSet::new();
        for service in &self.services {
            if !names.insert(service.name.as_str()) {
                bail!("duplicate service name: {}", service.name);
            }
            if service.hosts.is_empty() {
                bail!("service {} has no hosts", service.name);
            }
            if service.value_template.matches("{secret}").count() != 1 {
                bail!(
                    "service {} value_template must contain one {{secret}}",
                    service.name
                );
            }
            if service.placeholder.contains("{secret}") {
                bail!(
                    "service {} placeholder must not contain {{secret}}",
                    service.name
                );
            }
            if let Some(refs) = &vault_refs
                && !refs.contains(service.secret_ref.as_str())
            {
                bail!(
                    "service {} references an unmapped Vaultwarden item",
                    service.name
                );
            }
            for host in &service.hosts {
                let normalized = host.to_ascii_lowercase();
                if host.contains('*') || host.contains('/') || host.contains(':') {
                    bail!(
                        "service {} has invalid exact hostname: {host}",
                        service.name
                    );
                }
                if !hosts.insert(normalized) {
                    bail!("destination hostname appears in multiple policies: {host}");
                }
            }
        }

        self.validate_capabilities()
    }

    fn validate_realm(&self) -> Result<()> {
        for (name, value) in [
            ("realm id", self.realm.id.as_str()),
            ("realm tenant", self.realm.tenant.as_str()),
            ("realm persona", self.realm.persona.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                bail!("{name} is invalid");
            }
        }
        if self.realm.generation == 0 {
            bail!("realm generation must be positive");
        }
        Ok(())
    }

    fn validate_upstream_proxy(&self) -> Result<()> {
        let Some(proxy) = &self.upstream_proxy else {
            return Ok(());
        };
        let url = reqwest::Url::parse(&proxy.url).context("upstream proxy URL is invalid")?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            bail!("upstream proxy URL must use HTTP(S) and include a host");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("upstream proxy URL must not embed credentials");
        }
        match (&proxy.username, &proxy.password_file) {
            (None, None) => Ok(()),
            (Some(username), Some(path)) => {
                if username.is_empty() || username.contains([':', '\r', '\n']) {
                    bail!("upstream proxy username is invalid");
                }
                if !path.is_absolute() {
                    bail!("upstream proxy password_file must be absolute");
                }
                Ok(())
            }
            _ => bail!("upstream proxy username and password_file must be configured together"),
        }
    }

    fn validate_identity(&self) -> Result<()> {
        if self.identity.issuer.is_empty() || self.identity.audience.is_empty() {
            bail!("identity issuer and audience must not be empty");
        }
        if self.identity.max_ttl_seconds == 0 {
            bail!("identity max_ttl_seconds must be positive");
        }
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.identity.public_key)
            .context("identity public_key is not valid base64")?;
        if public_key.len() != 32 {
            bail!("identity public_key must contain 32 bytes");
        }
        Ok(())
    }

    fn validate_capabilities(&self) -> Result<()> {
        let service_names: HashSet<&str> = self
            .services
            .iter()
            .map(|item| item.name.as_str())
            .collect();
        let mut capability_names = HashSet::new();
        for capability in &self.capabilities {
            if capability.name.is_empty() || capability.persona.is_empty() {
                bail!("capability name and persona must not be empty");
            }
            if !capability_names.insert(capability.name.as_str()) {
                bail!("duplicate capability name: {}", capability.name);
            }
            if capability.persona != self.realm.persona {
                bail!(
                    "capability {} belongs to another persona realm",
                    capability.name
                );
            }
            if !service_names.contains(capability.service.as_str()) {
                bail!(
                    "capability {} references an unknown service",
                    capability.name
                );
            }
            if let ProviderConfig::Vaultwarden(provider) = &self.provider {
                let service = self
                    .services
                    .iter()
                    .find(|service| service.name == capability.service)
                    .context("validated capability service disappeared")?;
                let mapping = provider
                    .items
                    .iter()
                    .find(|mapping| mapping.secret_ref == service.secret_ref)
                    .context("validated Vaultwarden mapping disappeared")?;
                if mapping.persona != capability.persona {
                    bail!(
                        "capability {} persona does not own its Vaultwarden item",
                        capability.name
                    );
                }
            }
            if capability.methods.is_empty() || capability.paths.is_empty() {
                bail!(
                    "capability {} must declare methods and paths",
                    capability.name
                );
            }
            for method in &capability.methods {
                let parsed: http::Method = method.parse().with_context(|| {
                    format!("capability {} has invalid method", capability.name)
                })?;
                if parsed.as_str() != method {
                    bail!(
                        "capability {} methods must use canonical uppercase",
                        capability.name
                    );
                }
            }
            for path in &capability.paths {
                if !path.starts_with('/') || path.contains('?') || path.contains('#') {
                    bail!("capability {} has invalid exact path", capability.name);
                }
            }
        }
        Ok(())
    }

    fn validate_provider(&self) -> Result<Option<HashSet<&str>>> {
        let ProviderConfig::Vaultwarden(provider) = &self.provider else {
            return Ok(None);
        };
        if !provider.cli_path.is_absolute()
            || !provider.appdata_dir.is_absolute()
            || !provider.session_file.is_absolute()
        {
            bail!("Vaultwarden CLI, appdata, and session-file paths must be absolute");
        }
        if provider.cache_ttl_seconds == 0 || provider.cache_ttl_seconds > 300 {
            bail!("Vaultwarden cache TTL must be between 1 and 300 seconds");
        }
        if provider.items.is_empty() {
            bail!("Vaultwarden provider requires explicit item mappings");
        }
        let mut refs = HashSet::new();
        let mut ids = HashSet::new();
        for item in &provider.items {
            if item.secret_ref.is_empty() || item.persona.is_empty() || !is_uuid(&item.item_id) {
                bail!("Vaultwarden item mapping is invalid");
            }
            if !refs.insert(item.secret_ref.as_str()) || !ids.insert(item.item_id.as_str()) {
                bail!("Vaultwarden item mappings must be unique");
            }
            if item.persona != self.realm.persona {
                bail!("Vaultwarden item belongs to another persona realm");
            }
        }
        Ok(Some(refs))
    }

    /// Resolve an exact destination host to one policy.
    #[must_use]
    pub fn service_for_host(&self, host: &str) -> Option<&ServicePolicy> {
        self.services.iter().find(|service| {
            service
                .hosts
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(host))
        })
    }

    /// Resolve one exact named capability.
    #[must_use]
    pub fn capability(&self, name: &str) -> Option<&CapabilityPolicy> {
        self.capabilities
            .iter()
            .find(|capability| capability.name == name)
    }
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    use super::{
        CapabilityPolicy, Config, IdentityConfig, ProviderConfig, RealmConfig, ServicePolicy,
        UpstreamProxyConfig, VaultItemMapping, VaultwardenConfig,
    };

    fn config() -> Config {
        Config {
            realm: RealmConfig {
                id: "realm-developer".into(),
                tenant: "tenant-one".into(),
                persona: "developer".into(),
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
                public_key: base64::engine::general_purpose::STANDARD.encode(
                    SigningKey::from_bytes(&[7_u8; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                max_ttl_seconds: 60,
                clock_skew_seconds: 2,
            },
            capabilities: vec![CapabilityPolicy {
                name: "github-user".into(),
                persona: "developer".into(),
                service: "github".into(),
                methods: vec!["GET".into()],
                paths: vec!["/user".into()],
            }],
            services: vec![ServicePolicy {
                name: "github".into(),
                hosts: vec!["api.github.com".into()],
                header: "authorization".into(),
                placeholder: "Bearer charon-placeholder".into(),
                value_template: "Bearer {secret}".into(),
                secret_ref: "CHARON_GITHUB_TOKEN".into(),
            }],
        }
    }

    #[test]
    fn exact_host_match_is_case_insensitive() {
        assert_eq!(
            config()
                .service_for_host("API.GITHUB.COM")
                .map(|p| p.name.as_str()),
            Some("github")
        );
    }

    #[test]
    fn wildcard_hosts_are_rejected() {
        let mut candidate = config();
        candidate.services[0].hosts = vec!["*.github.com".into()];
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn capability_must_reference_a_service() {
        let mut candidate = config();
        candidate.capabilities[0].service = "missing".into();
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn realm_rejects_mixed_personas_and_zero_generation() {
        let mut candidate = config();
        candidate.capabilities[0].persona = "bob".into();
        assert!(candidate.validate().is_err());

        let mut candidate = config();
        candidate.realm.generation = 0;
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn upstream_proxy_credentials_require_a_protected_file() {
        let mut embedded = config();
        embedded.upstream_proxy = Some(UpstreamProxyConfig {
            url: "http://egress:secret@egress.test:8888".into(),
            username: None,
            password_file: None,
        });
        assert!(embedded.validate().is_err());

        let mut incomplete = config();
        incomplete.upstream_proxy = Some(UpstreamProxyConfig {
            url: "http://egress.test:8888".into(),
            username: Some("egress".into()),
            password_file: None,
        });
        assert!(incomplete.validate().is_err());

        let mut protected = config();
        protected.upstream_proxy = Some(UpstreamProxyConfig {
            url: "http://egress.test:8888".into(),
            username: Some("egress".into()),
            password_file: Some("/run/credentials/egress-password".into()),
        });
        assert!(protected.validate().is_ok());
    }

    #[test]
    fn vaultwarden_requires_exact_bounded_mappings() {
        let mut candidate = config();
        candidate.services[0].secret_ref = "github/developer".into();
        candidate.provider = ProviderConfig::Vaultwarden(VaultwardenConfig {
            cli_path: "/usr/local/bin/bw".into(),
            appdata_dir: "/var/lib/charon/bw".into(),
            session_file: "/run/credentials/bw-session".into(),
            cache_ttl_seconds: 30,
            items: vec![VaultItemMapping {
                secret_ref: "github/developer".into(),
                persona: "developer".into(),
                item_id: "00000000-0000-4000-8000-000000000001".into(),
            }],
        });
        assert!(candidate.validate().is_ok());

        candidate.services[0].secret_ref = "github/another-persona".into();
        assert!(candidate.validate().is_err());

        candidate.services[0].secret_ref = "github/developer".into();
        let ProviderConfig::Vaultwarden(provider) = &mut candidate.provider else {
            panic!("test provider must be Vaultwarden");
        };
        provider.items[0].persona = "another-persona".into();
        assert!(candidate.validate().is_err());
    }
}
