//! Binding a listener. With no address configured it tries the IPv6 wildcard first and the IPv4
//! wildcard second, so a host with either stack serves.

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
    fn candidates() {
        assert_eq!(bind_candidates("", 80), ["[::]:80", "0.0.0.0:80"]);
        assert_eq!(bind_candidates("127.0.0.1", 80), ["127.0.0.1:80"]);
    }
}
