//! Charon process entry point.

use std::{future::IntoFuture as _, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use charon::{
    ca,
    config::Config,
    provider,
    proxy::{AppState, app, serve_transparent},
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "charon=info".into()))
        .init();

    let command = parse_command()?;
    let config_path = match command {
        Command::Healthcheck(url) => return healthcheck(&url).await,
        Command::CaGenerate {
            name,
            certificate,
            private_key,
        } => {
            return ca::generate(&name, &certificate, &private_key);
        }
        Command::CaValidate {
            certificate,
            private_key,
        } => {
            println!("{}", ca::validate(&certificate, &private_key)?);
            return Ok(());
        }
        Command::CaFingerprint(certificate) => {
            println!("{}", ca::fingerprint(&certificate)?);
            return Ok(());
        }
        Command::CaExport {
            certificate,
            output,
        } => {
            return ca::export(&certificate, &output);
        }
        Command::PolicyValidate(path) => {
            let _ = Config::load(&path)?;
            println!("valid");
            return Ok(());
        }
        Command::PolicyInventory(path) => {
            let config = Config::load(&path)?;
            let inventory = config
                .capabilities
                .iter()
                .map(|capability| {
                    serde_json::json!({
                        "capability": capability.name,
                        "service": capability.service,
                        "methods": capability.methods,
                        "paths": capability.paths,
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&inventory)?);
            return Ok(());
        }
        Command::Serve(config_path) => config_path,
    };
    let config = Config::load(&config_path)?;
    let listen = config.listen;
    let secrets = provider::build(&config.provider)?;
    let transparent = config
        .services
        .iter()
        .filter_map(|service| {
            service
                .transparent_listen
                .map(|address| (service.name.clone(), address))
        })
        .collect::<Vec<_>>();
    let state = std::sync::Arc::new(AppState::new(config, secrets)?);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;
    info!(%listen, "charon listening");
    let mut transparent_listeners = Vec::new();
    for (service, address) in transparent {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind transparent listener {address}"))?;
        transparent_listeners.push((service, listener));
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    for (service, listener) in transparent_listeners {
        let state = std::sync::Arc::clone(&state);
        let shutdown = shutdown_rx.clone();
        tasks.spawn(async move { serve_transparent(listener, state, service, shutdown).await });
    }
    let control_shutdown = shutdown_rx.clone();
    let control = axum::serve(listener, app(state))
        .with_graceful_shutdown(async move {
            let mut shutdown = control_shutdown;
            let _ = shutdown.changed().await;
        })
        .into_future();
    tokio::pin!(control);
    tokio::select! {
        result = &mut control => result.context("server failed")?,
        () = shutdown_signal() => {
            let _ = shutdown_tx.send(true);
            control.await.context("server failed during graceful shutdown")?;
        }
        result = tasks.join_next(), if !tasks.is_empty() => {
            match result {
                Some(Ok(Ok(()))) => bail!("transparent listener stopped unexpectedly"),
                Some(Ok(Err(error))) => return Err(error.context("transparent listener failed")),
                Some(Err(error)) => return Err(error).context("transparent listener task failed"),
                None => bail!("transparent listener set stopped unexpectedly"),
            }
        }
    }
    let _ = shutdown_tx.send(true);
    while let Some(result) = tasks.join_next().await {
        result.context("transparent listener task failed")??;
    }
    Ok(())
}

enum Command {
    Serve(PathBuf),
    Healthcheck(String),
    CaGenerate {
        name: String,
        certificate: PathBuf,
        private_key: PathBuf,
    },
    CaValidate {
        certificate: PathBuf,
        private_key: PathBuf,
    },
    CaFingerprint(PathBuf),
    CaExport {
        certificate: PathBuf,
        output: PathBuf,
    },
    PolicyValidate(PathBuf),
    PolicyInventory(PathBuf),
}

fn parse_command() -> Result<Command> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [flag, path] if flag == "--config" => Ok(Command::Serve(path.into())),
        [command, url] if command == "healthcheck" => {
            Ok(Command::Healthcheck(url.clone().into_string().map_err(
                |_| anyhow::anyhow!("healthcheck URL must be valid UTF-8"),
            )?))
        }
        [ca, command, name, certificate, private_key] if ca == "ca" && command == "generate" => {
            Ok(Command::CaGenerate {
                name: name
                    .clone()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("CA name must be UTF-8"))?,
                certificate: certificate.into(),
                private_key: private_key.into(),
            })
        }
        [ca, command, certificate, private_key] if ca == "ca" && command == "validate" => {
            Ok(Command::CaValidate {
                certificate: certificate.into(),
                private_key: private_key.into(),
            })
        }
        [ca, command, certificate] if ca == "ca" && command == "fingerprint" => {
            Ok(Command::CaFingerprint(certificate.into()))
        }
        [ca, command, certificate, output] if ca == "ca" && command == "export" => {
            Ok(Command::CaExport {
                certificate: certificate.into(),
                output: output.into(),
            })
        }
        [policy, command, path] if policy == "policy" && command == "validate" => {
            Ok(Command::PolicyValidate(path.into()))
        }
        [policy, command, path] if policy == "policy" && command == "inventory" => {
            Ok(Command::PolicyInventory(path.into()))
        }
        _ => bail!(
            "usage: charon --config <path> | charon healthcheck <url> | charon policy validate <config> | charon policy inventory <config> | charon ca generate <name> <certificate> <private-key> | charon ca validate <certificate> <private-key> | charon ca fingerprint <certificate> | charon ca export <certificate> <output>"
        ),
    }
}

async fn healthcheck(url: &str) -> Result<()> {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build healthcheck client")?
        .get(url)
        .send()
        .await
        .with_context(|| format!("healthcheck request to {url} failed"))?;
    ensure!(
        response.status() == reqwest::StatusCode::NO_CONTENT,
        "healthcheck returned {}",
        response.status()
    );
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install ctrl-c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to install terminate handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
