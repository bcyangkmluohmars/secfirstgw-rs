// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal SSH diagnostic tool — connects to a device and runs a command.
//! Uses same russh + patched ssh-key as the gateway binary.

use anyhow::{Context, Result};
use russh::client;
use russh::ChannelMsg;
use std::sync::Arc;

struct SshHandler;

#[async_trait::async_trait]
impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: ssh-diag <host> <port> <user> <password> [command...]");
        eprintln!("Example: ssh-diag 10.0.0.50 22 sfgw_dev1 mypass cat /tmp/system.cfg");
        std::process::exit(1);
    }

    let host = &args[1];
    let port: u16 = args[2].parse().context("invalid port")?;
    let user = &args[3];
    let pass = &args[4];
    let cmd = if args.len() > 5 {
        args[5..].join(" ")
    } else {
        "cat /tmp/system.cfg".into()
    };

    eprintln!("[*] Connecting to {}:{}...", host, port);

    let config = Arc::new(client::Config {
        ..Default::default()
    });

    let mut session = client::connect(config, (host.as_str(), port), SshHandler)
        .await
        .context("SSH connect failed")?;

    // Try password auth, fallback to keyboard-interactive (Dropbear)
    let auth_ok = match session.authenticate_password(user, pass).await {
        Ok(true) => true,
        _ => {
            eprintln!("[*] Password auth failed, trying keyboard-interactive...");
            use russh::client::KeyboardInteractiveAuthResponse;
            match session
                .authenticate_keyboard_interactive_start(user, None)
                .await?
            {
                KeyboardInteractiveAuthResponse::Success => true,
                KeyboardInteractiveAuthResponse::Failure => false,
                KeyboardInteractiveAuthResponse::InfoRequest { .. } => {
                    match session
                        .authenticate_keyboard_interactive_respond(vec![pass.to_string()])
                        .await?
                    {
                        KeyboardInteractiveAuthResponse::Success => true,
                        _ => false,
                    }
                }
            }
        }
    };

    if !auth_ok {
        anyhow::bail!("authentication rejected");
    }

    eprintln!("[*] Authenticated. Running: {}", cmd);

    let mut channel = session.channel_open_session().await?;
    channel.exec(true, cmd.as_bytes()).await?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, .. }) => stderr.extend_from_slice(&data),
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                eprintln!("[*] Exit status: {}", exit_status);
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) => break,
            Some(_) => {}
            None => break,
        }
    }

    if !stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&stdout));
    }
    if !stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&stderr));
    }

    Ok(())
}
