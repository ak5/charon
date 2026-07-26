//! Charon process entry point.

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use charon::{
    config::Config,
    provider,
    proxy::{AppState, app},
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "charon=info".into()))
        .init();

    let command = parse_command()?;
    if let Command::Healthcheck(url) = command {
        return healthcheck(&url).await;
    }
    let Command::Serve(config_path) = command else {
        unreachable!("healthcheck returned above")
    };
    let config = Config::load(&config_path)?;
    let listen = config.listen;
    let secrets = provider::build(&config.provider)?;
    let state = std::sync::Arc::new(AppState::new(config, secrets)?);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;
    info!(%listen, "charon listening");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server failed")
}

enum Command {
    Serve(PathBuf),
    Healthcheck(String),
}

fn parse_command() -> Result<Command> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(path), None) if flag == "--config" => Ok(Command::Serve(path.into())),
        (Some(command), Some(url), None) if command == "healthcheck" => {
            Ok(Command::Healthcheck(url.into_string().map_err(|_| {
                anyhow::anyhow!("healthcheck URL must be valid UTF-8")
            })?))
        }
        _ => bail!("usage: charon --config <path> | charon healthcheck <url>"),
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
