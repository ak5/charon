//! Exact-host, IPv4-only, process-lifetime DNS pinning.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Resolver that denies unknown names, IPv6, unsafe service addresses, and
/// changes after the first successful resolution in one Charon process.
pub struct PinnedResolver {
    service_hosts: HashSet<String>,
    infrastructure_hosts: HashSet<String>,
    cache: Arc<Mutex<HashMap<String, Vec<SocketAddr>>>>,
}

impl PinnedResolver {
    /// Construct from exact service names and optional trusted egress names.
    #[must_use]
    pub fn new(service_hosts: HashSet<String>, infrastructure_hosts: HashSet<String>) -> Self {
        Self {
            service_hosts,
            infrastructure_hosts,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let hostname = name.as_str().to_ascii_lowercase();
        let cached = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&hostname).cloned());
        if let Some(addresses) = cached {
            return Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) });
        }
        let service = self.service_hosts.contains(&hostname);
        let infrastructure = self.infrastructure_hosts.contains(&hostname);
        if !service && !infrastructure {
            return Box::pin(async move {
                Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "DNS name is not authorized",
                ))
                    as Box<dyn std::error::Error + Send + Sync>)
            });
        }
        let cache = Arc::clone(&self.cache);
        Box::pin(async move {
            let resolved = tokio::net::lookup_host((hostname.as_str(), 0))
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            let addresses = resolved
                .filter(|address| match address.ip() {
                    IpAddr::V4(ip) => infrastructure || is_public_ipv4(ip),
                    IpAddr::V6(_) => false,
                })
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "DNS returned no authorized IPv4 address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            let addresses = cache
                .lock()
                .map_err(|_| {
                    Box::new(io::Error::other("DNS pin cache is unavailable"))
                        as Box<dyn std::error::Error + Send + Sync>
                })?
                .entry(hostname)
                .or_insert(addresses)
                .clone();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        || (ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19))
        || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 224)
}

#[cfg(test)]
mod tests {
    use super::is_public_ipv4;
    #[test]
    fn denies_nonpublic_and_metadata_ranges() {
        for ip in [
            [0, 0, 0, 1],
            [10, 0, 0, 1],
            [127, 0, 0, 1],
            [169, 254, 169, 254],
            [172, 16, 0, 1],
            [192, 168, 0, 1],
            [100, 64, 0, 1],
            [100, 100, 100, 200],
            [198, 18, 0, 1],
            [192, 0, 0, 8],
            [224, 0, 0, 1],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
        ] {
            assert!(!is_public_ipv4(ip.into()));
        }
        assert!(is_public_ipv4([8, 8, 8, 8].into()));
    }
}
