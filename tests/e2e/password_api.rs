//! Real local TLS password API reached through the fixture CONNECT intermediary.
use crate::tls::TlsAuthority;
use anyhow::Result;
use axum::{
    body::{Body, to_bytes},
    http::{Response, StatusCode},
};
use hyper_util::rt::TokioIo;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

pub async fn start(
    authority: &TlsAuthority,
    passwords: [SecretString; 2],
    calls: Arc<AtomicUsize>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let mut server = authority.server_config("password.test")?;
    Arc::make_mut(&mut server).alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let passwords = Arc::new(passwords);
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let server = server.clone();
            let passwords = passwords.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                // Fixture-only connector: no request to a public DNS address is made.
                let mut prelude = Vec::new();
                while !prelude.ends_with(b"\r\n\r\n") && prelude.len() < 4096 {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    prelude.push(byte[0]);
                }
                if !prelude.starts_with(b"CONNECT password.test:443 ") {
                    return;
                }
                if socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(tls) = TlsAcceptor::from(server).accept(socket).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let passwords = passwords.clone();
                        let calls = calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            let (name, index) = match request.uri().path() {
                                "/first" => ("first", 0),
                                "/second" => ("second", 1),
                                _ => ("unknown", 0),
                            };
                            let expected = SecretString::from(format!(
                                "Bearer {}",
                                passwords[index].expose_secret()
                            ));
                            let authenticated = name != "unknown"
                                && request.method() == http::Method::POST
                                && request
                                    .headers()
                                    .get(http::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    == Some(expected.expose_secret());
                            let upload = to_bytes(Body::new(request.into_body()), 4096).await;
                            let matched = authenticated
                                && upload.ok().and_then(|bytes| {
                                    serde_json::from_slice::<serde_json::Value>(&bytes).ok()
                                }) == Some(json!({"operation":"synthetic-e2e"}));
                            let body =
                                Body::from(json!({"ok":matched,"endpoint":name}).to_string());
                            let response = Response::builder()
                                .status(if matched {
                                    StatusCode::OK
                                } else {
                                    StatusCode::UNAUTHORIZED
                                })
                                .header("content-type", "application/json")
                                .body(body);
                            Ok::<_, Infallible>(
                                response.unwrap_or_else(|_| Response::new(Body::empty())),
                            )
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Ok((address, task))
}
