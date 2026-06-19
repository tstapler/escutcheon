use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

pub fn send_sequence(host: &str, ports: &[u16], proto: &str) -> anyhow::Result<()> {
    let target: Ipv4Addr = host.parse().or_else(|_| {
        use std::net::ToSocketAddrs;
        format!("{host}:0")
            .to_socket_addrs()?
            .find_map(|a| if let std::net::SocketAddr::V4(v4) = a { Some(*v4.ip()) } else { None })
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no IPv4 address"))
    })?;

    for &port in ports {
        match proto {
            "udp" => send_udp(target, port)?,
            _ => send_tcp(target, port)?,
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn send_udp(target: Ipv4Addr, port: u16) -> anyhow::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.send_to(&[], (target, port))?;
    Ok(())
}

fn send_tcp(target: Ipv4Addr, port: u16) -> anyhow::Result<()> {
    // Connection-refused is expected; we only need the SYN to land.
    let _ = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from((target, port)),
        Duration::from_millis(200),
    );
    Ok(())
}
