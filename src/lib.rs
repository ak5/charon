//! Charon's configuration, `KeePass` store, administration, and HTTP proxy primitives.

#[cfg(test)]
extern crate self as charon;

pub mod admin;
pub mod broker;
pub mod ca;
pub mod config;
pub mod dns;
pub mod identity;
pub mod keepass;

pub mod proxy;
pub mod receipt;
pub mod response;
pub mod telegram;
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_support;
pub mod tls;

pub mod gateway;
