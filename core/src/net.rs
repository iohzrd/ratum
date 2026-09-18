//! Binding a listener, and the address a per-address limit counts a peer under. With no address
//! configured a listener binds the IPv6 wildcard first and the IPv4 wildcard second, so a host
//! with either stack serves.

use std::net::{IpAddr, Ipv6Addr};

/// The address a per-address limit counts a peer under: an IPv4 address, or an IPv4-mapped
/// IPv6 one read as IPv4, as it is; any other IPv6 address by its /64 prefix, the smallest
/// block one subscriber is routed, so a host cannot take a fresh count from each address of
/// its prefix.
pub fn limit_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(prefix))
        }
        v4 => v4,
    }
}

fn bind_candidates(addr: &str, port: u16) -> Vec<String> {
    if addr.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else {
        vec![format!("{addr}:{port}")]
    }
}

pub fn bind_first<T, E: std::fmt::Display>(
    addr: &str,
    port: u16,
    open: impl Fn(&str) -> Result<T, E>,
) -> Result<T, String> {
    let mut last = String::new();
    for candidate in bind_candidates(addr, port) {
        match open(&candidate) {
            Ok(listener) => return Ok(listener),
            Err(e) => last = format!("{candidate}: {e}"),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_counts_ipv4_as_is_and_ipv6_by_its_64_prefix() {
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        assert_eq!(limit_key(v4), v4);
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(limit_key(mapped), v4);
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limit_key(a), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
        assert_eq!(limit_key(a), limit_key(b));
        assert_ne!(limit_key(a), limit_key(other));
    }

    #[test]
    fn candidates() {
        assert_eq!(bind_candidates("", 80), ["[::]:80", "0.0.0.0:80"]);
        assert_eq!(bind_candidates("127.0.0.1", 80), ["127.0.0.1:80"]);
    }
}
