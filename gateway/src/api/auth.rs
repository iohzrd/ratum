//! HTTP Basic authentication against `api.admin_password`, compared over the whole string rather
//! than returning at the first byte that differs, with a limit on the failed attempts one remote
//! address may make.

use super::Context;
use base64::Engine as _;
use ratum::http::{self, Reply, Request};
use ratum::lock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The failed attempts one remote address may make within `FAILURE_WINDOW`, counted from its
/// first failure. Past them, a request from the address that carries credentials is answered
/// 429 without the password being compared, until the window ends.
const MAX_FAILURES: u32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// The addresses whose failures are held at once. A failure from an address not held, while
/// this many are, first removes the windows that have ended and then, if none had, the address
/// whose window started first.
const MAX_TRACKED_ADDRESSES: usize = 1024;

struct Failures {
    window_start: Instant,
    count: u32,
}

/// The failed authentication attempts per remote address.
#[derive(Default)]
pub(super) struct FailedLogins(Mutex<HashMap<IpAddr, Failures>>);

impl FailedLogins {
    /// Whether `valid` accepts the credentials of a request from `ip`: `valid` is called only
    /// while the address is under its limit, and a false result counts as a failure. Err is
    /// the time left until the address's window ends, while it is over the limit.
    fn check(
        &self,
        ip: IpAddr,
        now: Instant,
        valid: impl FnOnce() -> bool,
    ) -> Result<bool, Duration> {
        let mut held = lock(&self.0);
        if let Some(f) = held.get(&ip) {
            let elapsed = now.saturating_duration_since(f.window_start);
            if elapsed >= FAILURE_WINDOW {
                held.remove(&ip);
            } else if f.count >= MAX_FAILURES {
                return Err(FAILURE_WINDOW - elapsed);
            }
        }
        if valid() {
            return Ok(true);
        }
        if let Some(f) = held.get_mut(&ip) {
            f.count += 1;
            return Ok(false);
        }
        if held.len() >= MAX_TRACKED_ADDRESSES {
            held.retain(|_, f| now.saturating_duration_since(f.window_start) < FAILURE_WINDOW);
        }
        if held.len() >= MAX_TRACKED_ADDRESSES
            && let Some(oldest) = held.iter().min_by_key(|(_, f)| f.window_start).map(|(a, _)| *a)
        {
            held.remove(&oldest);
        }
        held.insert(ip, Failures { window_start: now, count: 1 });
        Ok(false)
    }
}

pub(super) fn secure_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut acc = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        acc |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    acc == 0
}

/// Whether an Authorization header value is Basic credentials carrying `password`; the user
/// name is not compared.
fn basic_password_matches(value: &str, password: &str) -> bool {
    let Some(b64) = value.strip_prefix("Basic ") else { return false };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let decoded = String::from_utf8_lossy(&decoded);
    decoded.split_once(':').is_some_and(|(_, p)| secure_eq(p, password))
}

/// Whether the request carries the admin password. A request with no Authorization header is
/// not authorized and not counted as a failure; one whose credentials do not match is counted
/// against its remote address. Err is the 429 reply to an address over its failure limit.
pub(super) fn authorized(ctx: &Context, req: &Request) -> Result<bool, Reply> {
    let password = &ctx.gateway.config.api.admin_password;
    if password.is_empty() {
        return Ok(false);
    }
    let Some(value) = http::header_value(req, "Authorization") else { return Ok(false) };
    let ip = req.peer.ip().to_canonical();
    ctx.failed_logins
        .check(ip, Instant::now(), || basic_password_matches(&value, password))
        .map_err(too_many_failures)
}

fn too_many_failures(retry_after: Duration) -> Reply {
    let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    http::text(429, "Too many failed login attempts from this address; try again later.")
        .with_header(http::header("Retry-After", &seconds.to_string()))
}

pub(super) fn forbidden(why: &str) -> Reply {
    http::text(403, why)
}

pub(super) fn unauthorized() -> Reply {
    http::text(401, "This action requires admin access.")
        .with_header(http::header("WWW-Authenticate", "Basic realm=\"DATUM Gateway\""))
}

pub(super) fn admin_access(
    ctx: &Context,
    req: &Request,
    without_password: &str,
) -> Result<(), Reply> {
    if ctx.gateway.config.api.admin_password.is_empty() {
        Err(forbidden(without_password))
    } else if authorized(ctx, req)? {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

pub(super) fn settings_access(ctx: &Context, req: &Request) -> Result<(), Reply> {
    admin_access(ctx, req, "The settings page requires api.admin_password to be set.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_eq_compares_whole_strings() {
        assert!(secure_eq("abc", "abc"));
        assert!(!secure_eq("abc", "abd"));
        assert!(!secure_eq("abc", "ab"));
        assert!(!secure_eq("", "a"));
        assert!(secure_eq("", ""));
    }

    #[test]
    fn basic_credentials_match_on_the_password_alone() {
        let basic =
            |s: &str| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(s));
        assert!(basic_password_matches(&basic("admin:pw"), "pw"));
        assert!(basic_password_matches(&basic("anyone:pw"), "pw"));
        assert!(!basic_password_matches(&basic("admin:wrong"), "pw"));
        assert!(!basic_password_matches(&basic("no colon"), "pw"));
        assert!(!basic_password_matches("Bearer x", "pw"));
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    #[test]
    fn an_address_over_its_failures_is_refused_without_a_comparison_until_the_window_ends() {
        let logins = FailedLogins::default();
        let start = Instant::now();
        for _ in 0..MAX_FAILURES {
            assert_eq!(logins.check(ip(1), start, || false), Ok(false));
        }
        let compared = std::cell::Cell::new(false);
        let later = start + Duration::from_secs(10);
        let refused = logins.check(ip(1), later, || {
            compared.set(true);
            true
        });
        assert_eq!(refused, Err(FAILURE_WINDOW - Duration::from_secs(10)));
        assert!(!compared.get(), "the password is not compared while the address is refused");
        assert_eq!(logins.check(ip(2), later, || true), Ok(true), "another address is not");
        assert_eq!(logins.check(ip(1), start + FAILURE_WINDOW, || true), Ok(true));
    }

    #[test]
    fn a_success_is_not_a_failure() {
        let logins = FailedLogins::default();
        let now = Instant::now();
        for _ in 0..3 * MAX_FAILURES {
            assert_eq!(logins.check(ip(1), now, || true), Ok(true));
        }
        assert!(lock(&logins.0).is_empty());
    }

    #[test]
    fn the_table_holds_at_most_its_bound_and_drops_the_oldest_window() {
        let logins = FailedLogins::default();
        let start = Instant::now();
        for i in 0..MAX_TRACKED_ADDRESSES {
            let addr = IpAddr::from((i as u32 + 1).to_be_bytes());
            let _ = logins.check(addr, start + Duration::from_millis(i as u64), || false);
        }
        let first = IpAddr::from(1u32.to_be_bytes());
        assert!(lock(&logins.0).contains_key(&first));
        let _ = logins.check(ip(1), start + Duration::from_secs(1), || false);
        let held = lock(&logins.0);
        assert_eq!(held.len(), MAX_TRACKED_ADDRESSES);
        assert!(!held.contains_key(&first), "the window that started first is dropped");
        assert!(held.contains_key(&ip(1)));
    }
}
