//! Capability references and typed request/response mediation policy.

use std::fmt;

use anyhow::{Result, bail};
use http::HeaderName;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroize;

/// Maximum serialized capability-reference length accepted from a workload.
pub const MAX_CAPABILITY_REFERENCE_BYTES: usize = 256;

/// A validated public reference to a policy-owned capability.
///
/// The reference contains no provider or secret-store identifier. It is safe
/// to compare and report, but it is never sufficient authorization by itself.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityReference(String);

impl CapabilityReference {
    /// Parse exactly one complete `{{charon.<capability>}}` reference.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, nested, malformed, or non-canonical input.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.len() > MAX_CAPABILITY_REFERENCE_BYTES {
            bail!("capability reference has an invalid length");
        }
        let Some(name) = value
            .strip_prefix("{{charon.")
            .and_then(|value| value.strip_suffix("}}"))
        else {
            bail!("capability reference is malformed");
        };
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || name.starts_with('.')
            || name.ends_with('.')
            || name.contains("..")
            || value.matches("{{").count() != 1
            || value.matches("}}").count() != 1
        {
            bail!("capability reference is malformed");
        }
        Ok(Self(name.to_owned()))
    }

    /// Return the exact policy capability name.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CapabilityReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CapabilityReference")
            .field(&self.0)
            .finish()
    }
}

/// The only request locations in which Charon may hydrate a credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HydrationSink {
    /// Replace the complete HTTP Authorization field value.
    Authorization,
    /// Replace one exact configured API-key header.
    Header {
        /// Exact case-insensitive HTTP header name.
        name: String,
    },
    /// Render HTTP Basic authentication with a fixed policy-owned username.
    Basic {
        /// Fixed public username selected by policy.
        username: String,
    },
    /// Replace one complete, exact URL path component.
    PathComponent {
        /// Zero-based path-component index after the leading slash.
        index: usize,
    },
    /// Replace one exact query-parameter value. Disabled unless declared.
    QueryParameter {
        /// Exact query-parameter name.
        name: String,
    },
    /// Replace one value selected by an exact RFC 6901 JSON pointer.
    JsonField {
        /// Exact RFC 6901 pointer to one string value.
        pointer: String,
    },
    /// Replace one exact URL-encoded form field.
    FormField {
        /// Exact URL-encoded form field name.
        name: String,
    },
    /// Render Git smart-HTTP Basic authentication with a fixed username.
    GitSmartHttp {
        /// Fixed public Git HTTP username selected by policy.
        username: String,
    },
}

impl HydrationSink {
    /// Validate names and selectors before the listener opens.
    ///
    /// # Errors
    ///
    /// Rejects unsafe headers, usernames, selectors, and unbounded indexes.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Authorization => Ok(()),
            Self::Header { name } => {
                let header: HeaderName = name
                    .parse()
                    .map_err(|_| anyhow::anyhow!("hydration header is invalid"))?;
                if is_forbidden_header(&header) || header == http::header::AUTHORIZATION {
                    bail!("hydration header is forbidden");
                }
                Ok(())
            }
            Self::Basic { username } | Self::GitSmartHttp { username } => {
                if username.is_empty()
                    || username.len() > 128
                    || username.contains([':', '\r', '\n'])
                {
                    bail!("basic-auth username is invalid");
                }
                Ok(())
            }
            Self::PathComponent { index } => {
                if *index > 64 {
                    bail!("path-component index exceeds the configured bound");
                }
                Ok(())
            }
            Self::QueryParameter { name } | Self::FormField { name } => {
                if !is_field_name(name) {
                    bail!("hydration field name is invalid");
                }
                Ok(())
            }
            Self::JsonField { pointer } => {
                if pointer.is_empty()
                    || pointer.len() > 256
                    || !pointer.starts_with('/')
                    || pointer.contains(['\r', '\n'])
                {
                    bail!("JSON hydration pointer is invalid");
                }
                Ok(())
            }
        }
    }
}

/// Policy-selected response mediation strategy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResponseMode {
    /// Parse and emit one bounded SSE event at a time.
    StructuredStream {
        /// Record framing to parse.
        format: StructuredStreamFormat,
        /// Maximum bytes retained for one event or record.
        max_record_bytes: usize,
        /// Exact object keys removed at every nesting level.
        forbidden_fields: Vec<String>,
    },
    /// Buffer and sanitize one small structured document.
    BufferedStructured {
        /// Maximum complete document size.
        max_bytes: usize,
        /// Exact object keys removed at every nesting level.
        forbidden_fields: Vec<String>,
    },
    /// Incrementally redact protected values with a bounded overlap window.
    TextStream,
    /// Stream a body without semantic inspection after strict media checks.
    OpaqueStream {
        /// Exact media types permitted for uninterpreted body bytes.
        content_types: Vec<String>,
    },
}

/// Structured record framing supported by the streaming sanitizer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum StructuredStreamFormat {
    /// Server-sent events separated by an empty line.
    Sse,
    /// One JSON value per newline.
    Ndjson,
}

/// Compression behavior for a mediated response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CompressionPolicy {
    /// Ask the upstream for identity encoding and reject encoded responses.
    IdentityOnly,
    /// Reserved for a future bounded decompress/sanitize/recompress mode.
    /// Current policy validation rejects this value.
    Opaque,
    /// Reject any upstream content encoding.
    Reject,
}

/// Render a policy-owned credential without exposing it through a return type.
pub(crate) fn render_secret(template: &str, secret: &SecretString) -> Result<SecretString> {
    if template.matches("{secret}").count() != 1 {
        bail!("credential template must contain exactly one secret marker");
    }
    let mut rendered = template.replace("{secret}", secret.expose_secret());
    let output = SecretString::from(rendered.clone());
    rendered.zeroize();
    Ok(output)
}

fn is_forbidden_header(header: &HeaderName) -> bool {
    matches!(
        header.as_str(),
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret as _, SecretString};

    use super::{CapabilityReference, HydrationSink, render_secret};

    #[test]
    fn capability_reference_is_exact_and_bounded() {
        let reference = CapabilityReference::parse("{{charon.github.read}}")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reference.capability(), "github.read");
        for invalid in [
            "charon.github.read",
            "{{charon.}}",
            "{{charon..read}}",
            "prefix {{charon.github.read}}",
            "{{charon.github.read}}{{charon.other}}",
            "{{{{charon.github.read}}}}",
        ] {
            assert!(CapabilityReference::parse(invalid).is_err(), "{invalid}");
        }
        assert!(CapabilityReference::parse(&"x".repeat(257)).is_err());
    }

    #[test]
    fn typed_sinks_reject_ambiguous_or_routing_fields() {
        assert!(HydrationSink::Authorization.validate().is_ok());
        assert!(
            HydrationSink::Header {
                name: "x-api-key".into()
            }
            .validate()
            .is_ok()
        );
        assert!(
            HydrationSink::Header {
                name: "host".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            HydrationSink::Basic {
                username: "bad:user".into()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn rendering_returns_a_secret_holding_value() {
        let rendered = render_secret("Bearer {secret}", &SecretString::from("fixture-value"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(rendered.expose_secret(), "Bearer fixture-value");
        assert!(render_secret("{secret}:{secret}", &SecretString::from("x")).is_err());
    }
}
