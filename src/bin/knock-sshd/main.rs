use clap::Parser;
use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet_datalink::{self as datalink, Channel};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(name = "knock-sshd", about = "Port-knock daemon — listens for sequences and opens the firewall")]
struct Args {
    #[arg(short, long, default_value = "/etc/escutcheon/sshd.toml")]
    config: PathBuf,
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Config {
    sequence: Vec<u16>,
    #[serde(default = "default_proto")]
    proto: String,
    open_port: u16,
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
    #[serde(default = "default_open_secs")]
    open_secs: u64,
    firewall: FirewallBackend,
    #[serde(default)]
    interface: Option<String>,
}

fn default_proto() -> String { "tcp".into() }
fn default_ttl() -> u64 { 10 }
fn default_open_secs() -> u64 { 30 }

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum FirewallBackend { Ufw, Firewalld, Iptables, Nftables, Pf }

// ── Per-IP knock state ────────────────────────────────────────────────────────

#[derive(Debug)]
struct KnockState {
    next_idx: usize,
    last_seen: Instant,
}

impl KnockState {
    fn new() -> Self { Self { next_idx: 0, last_seen: Instant::now() } }
    fn is_expired(&self, ttl: Duration) -> bool { self.last_seen.elapsed() > ttl }
}

// ── Firewall dispatch ─────────────────────────────────────────────────────────

fn firewall_open(backend: FirewallBackend, ip: Ipv4Addr, port: u16) -> anyhow::Result<()> {
    let ip_s = ip.to_string();
    let port_s = port.to_string();

    if backend == FirewallBackend::Pf {
        let rule = format!("pass in quick on egress proto tcp from {ip_s} to any port {port_s}\n");
        std::process::Command::new("pfctl")
            .args(["-a", "escutcheon", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| { use std::io::Write; c.stdin.as_mut().unwrap().write_all(rule.as_bytes())?; c.wait() })?;
        return Ok(());
    }

    let fd_rule;
    let nft_rule;
    let args: Vec<&str> = match backend {
        FirewallBackend::Ufw => vec!["ufw", "allow", "from", &ip_s, "to", "any", "port", &port_s, "proto", "tcp"],
        FirewallBackend::Firewalld => {
            fd_rule = format!("rule family=ipv4 source address={ip_s} port port={port_s} protocol=tcp accept");
            vec!["firewall-cmd", "--add-rich-rule", &fd_rule]
        }
        FirewallBackend::Iptables => vec!["iptables", "-I", "INPUT", "-s", &ip_s, "-p", "tcp", "--dport", &port_s, "-j", "ACCEPT"],
        FirewallBackend::Nftables => {
            nft_rule = format!("ip saddr {ip_s} tcp dport {port_s} accept");
            vec!["nft", "add", "rule", "inet", "filter", "input", &nft_rule]
        }
        FirewallBackend::Pf => unreachable!(),
    };
    let status = std::process::Command::new(args[0]).args(&args[1..]).status()?;
    anyhow::ensure!(status.success(), "{} exited {status}", args[0]);
    Ok(())
}

fn firewall_close(backend: FirewallBackend, ip: Ipv4Addr, port: u16) -> anyhow::Result<()> {
    let ip_s = ip.to_string();
    let port_s = port.to_string();

    if backend == FirewallBackend::Pf {
        let _ = std::process::Command::new("pfctl").args(["-a", "escutcheon", "-F", "rules"]).status();
        return Ok(());
    }
    if backend == FirewallBackend::Nftables {
        warn!("nftables auto-close not implemented — rule for {ip_s}:{port_s} must be removed manually");
        return Ok(());
    }

    let fd_rule;
    let args: Vec<&str> = match backend {
        FirewallBackend::Ufw => vec!["ufw", "delete", "allow", "from", &ip_s, "to", "any", "port", &port_s, "proto", "tcp"],
        FirewallBackend::Firewalld => {
            fd_rule = format!("rule family=ipv4 source address={ip_s} port port={port_s} protocol=tcp accept");
            vec!["firewall-cmd", "--remove-rich-rule", &fd_rule]
        }
        FirewallBackend::Iptables => vec!["iptables", "-D", "INPUT", "-s", &ip_s, "-p", "tcp", "--dport", &port_s, "-j", "ACCEPT"],
        FirewallBackend::Nftables | FirewallBackend::Pf => unreachable!(),
    };
    let _ = std::process::Command::new(args[0]).args(&args[1..]).status();
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let raw = std::fs::read_to_string(&args.config)
        .map_err(|e| anyhow::anyhow!("cannot read {:?}: {e}", args.config))?;
    let cfg: Arc<Config> = Arc::new(toml::from_str(&raw)?);

    info!(
        sequence = ?cfg.sequence,
        port = cfg.open_port,
        firewall = ?cfg.firewall,
        "knock-sshd started"
    );

    let states: Arc<DashMap<Ipv4Addr, KnockState>> = Arc::new(DashMap::new());

    // Expiry sweeper
    {
        let states = Arc::clone(&states);
        let ttl = Duration::from_secs(cfg.ttl_secs);
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                states.retain(|_, v| !v.is_expired(ttl));
            }
        });
    }

    // Packet capture (blocking — runs on a dedicated thread)
    let cfg2 = Arc::clone(&cfg);
    let states2 = Arc::clone(&states);
    tokio::task::spawn_blocking(move || capture_loop(cfg2, states2))
        .await??;

    Ok(())
}

fn capture_loop(cfg: Arc<Config>, states: Arc<DashMap<Ipv4Addr, KnockState>>) -> anyhow::Result<()> {
    let interfaces = datalink::interfaces();
    let iface = match &cfg.interface {
        Some(name) => interfaces.into_iter().find(|i| &i.name == name)
            .ok_or_else(|| anyhow::anyhow!("interface {name} not found"))?,
        None => interfaces.into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
            .ok_or_else(|| anyhow::anyhow!("no suitable network interface found"))?,
    };

    info!(iface = %iface.name, "capturing packets");

    let (_, mut rx) = match datalink::channel(&iface, Default::default())? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => anyhow::bail!("unsupported channel type"),
    };

    let ttl = Duration::from_secs(cfg.ttl_secs);
    let open_dur = Duration::from_secs(cfg.open_secs);

    loop {
        match rx.next() {
            Ok(frame) => {
                if let Some((src_ip, dst_port)) = extract_dst_port(frame, &cfg.proto) {
                    handle_packet(src_ip, dst_port, &cfg, &states, ttl, open_dur);
                }
            }
            Err(e) => warn!("packet recv error: {e}"),
        }
    }
}

fn extract_dst_port(frame: &[u8], proto: &str) -> Option<(Ipv4Addr, u16)> {
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ipv4::Ipv4Packet;

    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }
    let ip = Ipv4Packet::new(eth.payload())?;
    let src = ip.get_source();

    match proto {
        "udp" if ip.get_next_level_protocol() == IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(ip.payload())?;
            Some((src, udp.get_destination()))
        }
        _ if ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(ip.payload())?;
            // Only SYN packets count (flags & 0x02 != 0, ACK == 0)
            let flags = tcp.get_flags();
            if flags & 0x02 != 0 && flags & 0x10 == 0 {
                Some((src, tcp.get_destination()))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn handle_packet(
    src: Ipv4Addr,
    port: u16,
    cfg: &Config,
    states: &DashMap<Ipv4Addr, KnockState>,
    ttl: Duration,
    open_dur: Duration,
) {
    let expected = cfg.sequence[states.get(&src).map(|s| s.next_idx).unwrap_or(0)];
    if port != expected {
        if states.contains_key(&src) {
            debug!(%src, port, expected, "wrong knock — resetting state");
            states.remove(&src);
        }
        return;
    }

    let mut entry = states.entry(src).or_insert_with(KnockState::new);
    if entry.is_expired(ttl) {
        debug!(%src, "TTL expired — resetting state for that IP");
        entry.next_idx = 0;
    }
    entry.next_idx += 1;
    entry.last_seen = Instant::now();

    if entry.next_idx < cfg.sequence.len() {
        debug!(%src, progress = entry.next_idx, total = cfg.sequence.len(), "knock in progress");
        return;
    }

    // Complete sequence — drop state and open firewall
    drop(entry);
    states.remove(&src);
    info!(%src, port = cfg.open_port, "sequence complete — opening firewall");

    let backend = cfg.firewall;
    let open_port = cfg.open_port;

    match firewall_open(backend, src, open_port) {
        Ok(()) => info!(%src, "firewall opened"),
        Err(e) => warn!(%src, "firewall open failed: {e}"),
    }

    // Schedule close
    tokio::spawn(async move {
        time::sleep(open_dur).await;
        if let Err(e) = firewall_close(backend, src, open_port) {
            warn!(%src, "firewall close failed: {e}");
        } else {
            info!(%src, "firewall closed");
        }
    });
}
