//! Records the git commit the source was built from, so a running binary can report which
//! revision it is. The `ratum` library's build script (`core/Cargo.toml`: `build =
//! "../build.rs"`); Cargo runs it with `core/` as the working directory. The value is set as
//! the `RATUM_GIT_COMMIT` compile-time environment variable and read by `ratum::VERSION` and
//! `ratum::GIT_COMMIT`, which every binary reports. It is "unknown" when the source is not a git
//! checkout (a release tarball) or `git` is not installed, so a build never fails over it.
//! A build outside the checkout that knows the commit (a container build whose context has
//! no `.git`, see `ratum-deploy/Dockerfile.pool`) passes it in as `RATUM_GIT_COMMIT` in the
//! build environment, which takes precedence over asking git.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RATUM_GIT_COMMIT");
    let commit = match std::env::var("RATUM_GIT_COMMIT") {
        Ok(given) if !given.trim().is_empty() => given.trim().to_string(),
        _ => describe(),
    };
    println!("cargo:rustc-env=RATUM_GIT_COMMIT={commit}");
    for path in rerun_paths() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

/// The abbreviated commit hash, with `-dirty` appended when a tracked file differs from it.
fn describe() -> String {
    let Some(hash) = git(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_string();
    };
    match git(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(changes) if !changes.is_empty() => format!("{hash}-dirty"),
        _ => hash,
    }
}

/// The paths whose change re-runs this script: `Cargo.toml` and `src` so the `-dirty` marker
/// follows source edits, `HEAD` and the ref it names so a commit or a checkout is picked up
/// even when no file content changed. Editing a tracked file outside `Cargo.toml` and `src`
/// (the README, a test) does not re-run the script, so the marker can be one build behind.
fn rerun_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("Cargo.toml"), PathBuf::from("src")];
    let mut git_path = |name: &str| {
        // `--git-path` resolves the real location, which is not `.git/<name>` in a worktree.
        if let Some(p) = git(&["rev-parse", "--git-path", name]) {
            paths.push(PathBuf::from(p));
        }
    };
    git_path("HEAD");
    git_path("packed-refs");
    if let Some(head_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        git_path(&head_ref);
    }
    // A path that does not exist counts as changed on every build, so drop the ones that are
    // absent (`packed-refs` in a repository that has never been packed, a detached HEAD).
    paths.retain(|p| p.exists());
    paths
}

/// The trimmed stdout of a git command, or `None` if git is missing or the command failed.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}
