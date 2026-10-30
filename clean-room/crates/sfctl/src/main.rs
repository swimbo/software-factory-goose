//! `sfctl` — the factory CLI. The human surface over the control plane's HTTP API.
//!
//! UX (see ux-plan.md): predictable subcommands, `--json` for scripting, exit 0 on success,
//! nothing destructive is silent (approve/deny are explicit).

use clap::{Parser, Subcommand};
mod private;
use serde_json::json;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "sfctl", version, about = "Clean-room software factory CLI")]
struct Cli {
    /// Base URL of the control plane (default $SFCTL_URL or http://localhost:8081).
    #[arg(
        long,
        global = true,
        env = "SFCTL_URL",
        default_value = "http://localhost:8081"
    )]
    url: String,

    /// Emit machine-readable JSON on stdout.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Use the separately authenticated local operator sockets.
    Private {
        #[command(subcommand)]
        command: private::PrivateCommand,
    },
    /// Submit an intent; the qualifier returns a lane.
    Submit {
        #[arg(long)]
        title: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        acceptance: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Inspect an intent's qualifier decision.
    Inspect { id: String },
    /// List active work packages with stage/spend/revision.
    Status { id: Option<String> },
    /// Approve a first-promotion or a privileged credential grant (Gate 1/3).
    Approve {
        kind: String,
        id: String,
        #[arg(long)]
        reason: String,
    },
    /// Deny a gate decision.
    Deny {
        kind: String,
        id: String,
        #[arg(long)]
        reason: String,
    },
    /// Raise the budget envelope (Gate 2 — human only).
    Budget {
        #[arg(long)]
        to_usd: f64,
    },
    /// Stop a work package (kill switch).
    Stop { id: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let Cli { url, json, command } = cli;
    if let Command::Private { command } = command {
        return private::run(command, json).await;
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    match command {
        Command::Private { .. } => unreachable!("handled above"),
        Command::Submit {
            title,
            description,
            acceptance,
            repo,
        } => {
            let body = json!({
                "title": title,
                "description": description,
                "acceptance": acceptance,
                "repo": repo,
            });
            let resp = client
                .post(format!("{url}/v1/intents"))
                .json(&body)
                .send()
                .await?;
            print_resp(json, resp).await
        }
        Command::Inspect { id } => {
            validate_identifier(&id)?;
            let resp = client.get(format!("{url}/v1/intents/{id}")).send().await?;
            print_resp(json, resp).await
        }
        Command::Status { id } => {
            let url = match id {
                Some(id) => {
                    validate_identifier(&id)?;
                    format!("{url}/v1/work-packages/{id}")
                }
                None => format!("{url}/v1/work-packages"),
            };
            let resp = client.get(url).send().await?;
            print_resp(json, resp).await
        }
        Command::Approve { kind, id, reason } => {
            validate_gate(&kind, &id)?;
            let url = format!("{url}/v1/{kind}/{id}/approve");
            let resp = client
                .post(url)
                .json(&json!({"reason": reason}))
                .send()
                .await?;
            print_resp(json, resp).await
        }
        Command::Deny { kind, id, reason } => {
            validate_gate(&kind, &id)?;
            let url = format!("{url}/v1/{kind}/{id}/deny");
            let resp = client
                .post(url)
                .json(&json!({"reason": reason}))
                .send()
                .await?;
            print_resp(json, resp).await
        }
        Command::Budget { to_usd } => {
            let resp = client
                .post(format!("{url}/v1/budget/raise"))
                .json(&json!({"to_usd": to_usd}))
                .send()
                .await?;
            print_resp(json, resp).await
        }
        Command::Stop { id } => {
            validate_identifier(&id)?;
            let resp = client
                .post(format!("{url}/v1/work-packages/{id}/stop"))
                .send()
                .await?;
            print_resp(json, resp).await
        }
    }
}

fn validate_identifier(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !id.is_empty()
            && id.len() <= 256
            && id != "."
            && id != ".."
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b)),
        "invalid identifier"
    );
    Ok(())
}

fn validate_gate(kind: &str, id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(matches!(kind, "promotions" | "grants"), "invalid gate kind");
    validate_identifier(id)
}

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

async fn print_resp(json: bool, mut resp: reqwest::Response) -> anyhow::Result<()> {
    let status = resp.status();
    anyhow::ensure!(
        resp.content_length()
            .is_none_or(|size| size <= MAX_RESPONSE_BYTES as u64),
        "response body exceeds limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        anyhow::ensure!(
            chunk.len() <= MAX_RESPONSE_BYTES - bytes.len(),
            "response body exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&bytes);
    if !status.is_success() {
        if json {
            println!("{text}");
        } else {
            println!("[{status}] {text}");
        }
        anyhow::bail!("request failed with status {status}");
    }
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| anyhow::anyhow!("server returned invalid JSON"))?;
    if json {
        println!("{text}");
    } else {
        println!("[{status}] {text}");
    }
    if value.get("error").is_some() {
        anyhow::bail!("server reported an operation error");
    }
    Ok(())
}
