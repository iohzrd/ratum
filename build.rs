use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RATUM_GIT_COMMIT");
    let commit = match std::env::var("RATUM_GIT_COMMIT") {
        Ok(given) if !given.trim().is_empty() => normalize(given.trim()),
        _ => describe(),
    };
    println!("cargo:rustc-env=RATUM_GIT_COMMIT={commit}");
    for path in rerun_paths() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn normalize(given: &str) -> String {
    let (body, dirty) = match given.strip_suffix("-dirty") {
        Some(body) => (body, "-dirty"),
        None => (given, ""),
    };
    let mut parts = body.rsplitn(3, '-');
    let hash = parts
        .next()
        .and_then(|g| g.strip_prefix('g'))
        .filter(|h| h.len() >= 4 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    let count =
        parts.next().is_some_and(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()));
    let body = match hash {
        Some(h) if count && parts.next().is_some() => h,
        _ => body,
    };
    let body = if body.len() > 12 && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        &body[..12]
    } else {
        body
    };
    format!("{body}{dirty}")
}

fn describe() -> String {
    let Some(hash) = git(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_string();
    };
    match git(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(changes) if !changes.is_empty() => format!("{hash}-dirty"),
        _ => hash,
    }
}

fn rerun_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("Cargo.toml"), PathBuf::from("src")];
    let mut git_path = |name: &str| {
        if let Some(p) = git(&["rev-parse", "--git-path", name]) {
            paths.push(PathBuf::from(p));
        }
    };
    git_path("HEAD");
    git_path("packed-refs");
    if let Some(head_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        git_path(&head_ref);
    }
    paths.retain(|p| p.exists());
    paths
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}
