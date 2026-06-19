use clap::Parser;
use escutcheon::{
    config::Config,
    knock::send_sequence,
    ttl::{record_knock, should_knock},
};
use std::os::unix::process::CommandExt;

#[derive(Parser)]
#[command(name = "knock-ssh", about = "SSH wrapper that fires a port-knock sequence before connecting")]
struct Args {
    /// Only send knock sequence; do not exec ssh
    #[arg(short = 'K', long)]
    knock_only: bool,

    /// SSH destination (user@host or host alias from config)
    destination: String,

    /// Remaining arguments passed through to ssh
    #[arg(trailing_var_arg = true)]
    ssh_args: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let cfg = Config::load()?;

    // Extract ProxyJump hosts from ssh_args (-J <host> or -o ProxyJump=<host>)
    let proxy_hosts = extract_proxy_hosts(&args.ssh_args);

    // Knock proxy hosts first
    for proxy in &proxy_hosts {
        knock_host(proxy, &cfg)?;
    }

    // Knock the destination
    let dest_host = strip_user(&args.destination);
    knock_host(dest_host, &cfg)?;

    if args.knock_only {
        return Ok(());
    }

    let ssh = which_ssh()?;
    let mut cmd = std::process::Command::new(&ssh);
    cmd.arg(&args.destination).args(&args.ssh_args);

    // exec() replaces the current process — no subprocess, no TTY issues
    let err = cmd.exec();
    Err(anyhow::anyhow!("exec {ssh:?} failed: {err}"))
}

fn knock_host(host: &str, cfg: &Config) -> anyhow::Result<()> {
    let host_cfg = cfg.resolve_host(host);

    let ports: Vec<u16> = host_cfg
        .and_then(|h| h.knock_ports.as_ref())
        .or(cfg.defaults.knock_ports.as_ref())
        .cloned()
        .unwrap_or_default();

    if ports.is_empty() {
        return Ok(());
    }

    let ttl_secs = host_cfg
        .and_then(|h| h.ttl_secs)
        .or(cfg.defaults.ttl_secs)
        .unwrap_or(0);

    if !should_knock(host, ttl_secs) {
        tracing::debug!("skipping knock for {host} — within TTL window");
        return Ok(());
    }

    let proto = host_cfg
        .and_then(|h| h.knock_proto.as_deref())
        .or(cfg.defaults.knock_proto.as_deref())
        .unwrap_or("tcp");

    send_sequence(host, &ports, proto)?;
    record_knock(host)?;
    Ok(())
}

/// Parse -J <host>[,<host>...] and -o ProxyJump=<host>[,<host>...] from ssh argv
fn extract_proxy_hosts(ssh_args: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut iter = ssh_args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "-J" {
            if let Some(val) = iter.next() {
                hosts.extend(parse_jump_list(val));
            }
        } else if let Some(val) = arg.strip_prefix("-J") {
            hosts.extend(parse_jump_list(val));
        } else if arg == "-o" {
            if let Some(val) = iter.next() {
                if let Some(jump) = val.strip_prefix("ProxyJump=") {
                    hosts.extend(parse_jump_list(jump));
                }
            }
        }
    }
    hosts
}

/// "user@host:port,host2" → ["host", "host2"]
fn parse_jump_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|entry| strip_user(entry.split(':').next().unwrap_or(entry)).to_owned())
        .collect()
}

fn strip_user(dest: &str) -> &str {
    dest.split('@').last().unwrap_or(dest)
}

fn which_ssh() -> anyhow::Result<std::path::PathBuf> {
    for candidate in ["/usr/bin/ssh", "/usr/local/bin/ssh", "/opt/homebrew/bin/ssh"] {
        let p = std::path::Path::new(candidate);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }
    Err(anyhow::anyhow!("ssh binary not found"))
}
