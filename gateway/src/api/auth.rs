//! HTTP Basic authentication against `api.admin_password`, compared over the whole string rather
//! than returning at the first byte that differs.

use super::Context;
use base64::Engine as _;
use ratum::http::{self, Reply};
use tiny_http::Request;

pub(super) fn secure_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut acc = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        acc |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    acc == 0
}

pub(super) fn authorized(ctx: &Context, req: &Request) -> bool {
    let password = &ctx.gateway.config.api.admin_password;
    if password.is_empty() {
        return false;
    }
    let Some(value) = http::header_value(req, "Authorization") else { return false };
    let Some(b64) = value.strip_prefix("Basic ") else { return false };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let decoded = String::from_utf8_lossy(&decoded);
    decoded.split_once(':').is_some_and(|(_, p)| secure_eq(p, password))
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
    } else if authorized(ctx, req) {
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
}
