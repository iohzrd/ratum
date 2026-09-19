//! The settings page's fields and what saving them does: each field names one key of the
//! configuration file, an edit is written into the file with the other keys and their order kept,
//! and the result is validated as at startup before it is written.

use crate::config::{
    COINBASE_UNIQUE_ID_RANGE, Config, DatumConfig, GLOBAL_TIMEOUT_MARGIN_SECS,
    MAX_CONFIGURED_TAG_LEN, MAX_CONFIGURED_TAGS_TOTAL_LEN, MAX_NETWORK_SHARE_BPS_RANGE, PORT_RANGE,
    VARDIFF_MIN_RANGE, WORK_UPDATE_SECONDS_RANGE,
};
use serde_json::{Value, json};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

struct Field {
    name: &'static str,
    label: &'static str,
    section: &'static str,
    key: &'static str,
    kind: FieldKind,
    current: fn(&Config) -> Value,
}

enum FieldKind {
    Text,
    /// A URL shown with its password redacted (`rpc::redact_url`); a redacted password
    /// submitted back is replaced by the file's.
    RedactedUrl,
    Int {
        min: i64,
        max: i64,
    },
    Bool,
    Password,
}

/// The form's bound for a configuration range, so a field's limits are declared once, in
/// `config.rs`, and both the page and the startup checks read them from there.
const fn int(range: &RangeInclusive<u64>) -> FieldKind {
    // A form field is submitted and parsed as an i64, so a range wider than that is offered
    // up to i64::MAX; the startup check still applies the range's own end.
    let end = *range.end();
    let max = if end > i64::MAX as u64 { i64::MAX } else { end as i64 };
    FieldKind::Int { min: *range.start() as i64, max }
}

/// A field named `<section>_<key>` for the key `section.key` of the file, whose current
/// value is read from the same field of `Config`.
macro_rules! field {
    ($section:ident . $key:ident, $label:literal, $kind:expr) => {
        Field {
            name: concat!(stringify!($section), "_", stringify!($key)),
            label: $label,
            section: stringify!($section),
            key: stringify!($key),
            kind: $kind,
            current: |c| json!(c.$section.$key),
        }
    };
}

const FIELDS: &[Field] = &[
    field!(mining.pool_address, "Bitcoin address", FieldKind::Text),
    field!(mining.coinbase_tag_secondary, "Coinbase tag", FieldKind::Text),
    field!(mining.coinbase_unique_id, "Unique gateway ID", int(&COINBASE_UNIQUE_ID_RANGE)),
    field!(datum.pool_port, "Pool port", int(&PORT_RANGE)),
    field!(datum.pool_pubkey, "Pool public key", FieldKind::Text),
    field!(datum.pool_url, "Pool web page", FieldKind::Text),
    field!(datum.protocol_v3, "Version 3 protocol", FieldKind::Bool),
    field!(stratum.listen_port, "Stratum port", int(&PORT_RANGE)),
    field!(stratum.vardiff_min, "Minimum difficulty", int(&VARDIFF_MIN_RANGE)),
    field!(
        stratum.max_network_share_bps,
        "Network hashrate limit",
        int(&MAX_NETWORK_SHARE_BPS_RANGE)
    ),
    field!(stratum.fingerprint_miners, "Fingerprint miners", FieldKind::Bool),
    field!(stratum.require_address_username, "Require an address as the username", FieldKind::Bool),
    field!(bitcoind.work_update_seconds, "Job update interval", int(&WORK_UPDATE_SECONDS_RANGE)),
    // Shown and compared in its redacted form, so the page never carries the password a
    // `user:password@` in the URL holds: a save that returns the redacted form unchanged keeps
    // the file's value, and one that edits another part of it keeps the file's password.
    Field {
        name: "bitcoind_rpcurl",
        label: "bitcoind RPC URL",
        section: "bitcoind",
        key: "rpcurl",
        kind: FieldKind::RedactedUrl,
        current: |c| json!(ratum::rpc::redact_url(&c.bitcoind.rpcurl)),
    },
    field!(bitcoind.rpcuser, "bitcoind RPC user", FieldKind::Text),
    field!(bitcoind.rpcpassword, "bitcoind RPC password", FieldKind::Password),
];

const OLD_POOL_HOST: &str = "pool_host(old)";

fn shown_pool_host(cfg: &Config, doc: &Value) -> String {
    if !cfg.datum.pool_host.is_empty() {
        return cfg.datum.pool_host.clone();
    }
    old_pool_host(doc).unwrap_or_else(|| DatumConfig::default().pool_host)
}

fn old_pool_host(doc: &Value) -> Option<String> {
    doc.get("datum")?.get(OLD_POOL_HOST)?.as_str().map(str::to_string)
}

fn secondary_tag_max(cfg: &Config) -> usize {
    MAX_CONFIGURED_TAGS_TOTAL_LEN
        .saturating_sub(cfg.mining.coinbase_tag_primary.len())
        .min(MAX_CONFIGURED_TAG_LEN)
}

fn username_behaviour(cfg: &Config) -> &'static str {
    if cfg.datum.pool_pass_full_users {
        "full_users"
    } else if cfg.datum.pool_pass_workers {
        "workers"
    } else {
        "private"
    }
}

fn reward_sharing(cfg: &Config) -> &'static str {
    if cfg.datum.pool_host.is_empty() {
        "never"
    } else if cfg.datum.pooled_mining_only {
        "require"
    } else {
        "prefer"
    }
}

pub fn form_values(cfg: &Config, doc: &Value) -> Value {
    let mut v = serde_json::Map::new();
    for f in FIELDS {
        if !matches!(f.kind, FieldKind::Password) {
            v.insert(f.name.into(), (f.current)(cfg));
        }
    }
    v.insert("username_behaviour".into(), json!(username_behaviour(cfg)));
    v.insert("reward_sharing".into(), json!(reward_sharing(cfg)));
    v.insert("datum_pool_host".into(), json!(shown_pool_host(cfg, doc)));
    v.insert("mining_coinbase_tag_secondary_max".into(), json!(secondary_tag_max(cfg)));
    Value::Object(v)
}

fn section<'a>(
    doc: &'a mut Value,
    name: &str,
) -> Result<&'a mut serde_json::Map<String, Value>, String> {
    let root = doc.as_object_mut().ok_or("the configuration file is not a JSON object")?;
    let entry = root.entry(name).or_insert_with(|| Value::Object(serde_json::Map::new()));
    entry.as_object_mut().ok_or_else(|| format!("the file's \"{name}\" is not a JSON object"))
}

struct Edit<'a> {
    doc: &'a mut Value,
    changed: bool,
    errors: Vec<String>,
}

impl Edit<'_> {
    fn set(&mut self, section_name: &str, key: &str, value: Value) {
        match section(self.doc, section_name) {
            Ok(s) => {
                s.insert(key.into(), value);
                self.changed = true;
            }
            Err(e) => self.errors.push(e),
        }
    }

    fn set_if_changed(&mut self, section_name: &str, key: &str, value: Value, current: Value) {
        if value != current {
            self.set(section_name, key, value);
        }
    }

    fn remove(&mut self, section_name: &str, key: &str) {
        if let Some(s) = self.doc.get_mut(section_name).and_then(Value::as_object_mut)
            && s.remove(key).is_some()
        {
            self.changed = true;
        }
    }
}

fn parse_int(label: &str, text: &str, min: i64, max: i64) -> Result<i64, String> {
    let v = text.trim().parse::<i64>().map_err(|_| format!("{label} must be a whole number"))?;
    if v < min || v > max {
        return Err(format!("{label} must be between {min} and {max}"));
    }
    Ok(v)
}

fn parse_bool(label: &str, text: &str) -> Result<bool, String> {
    match text.trim() {
        "1" | "true" | "on" => Ok(true),
        "0" | "false" | "off" | "" => Ok(false),
        _ => Err(format!("{label} must be 1 or 0")),
    }
}

fn render(doc: &Value) -> String {
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    serde::Serialize::serialize(doc, &mut ser).expect("a Value serializes");
    out.push(b'\n');
    String::from_utf8(out).expect("JSON is UTF-8")
}

fn submitted<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn apply_reward_sharing(edit: &mut Edit<'_>, cfg: &Config, form: &[(String, String)]) {
    let mut pool_host = cfg.datum.pool_host.clone();
    let default_host = DatumConfig::default().pool_host;
    match submitted(form, "reward_sharing") {
        None => {}
        Some(choice @ ("require" | "prefer")) => {
            let only = choice == "require";
            edit.set_if_changed(
                "datum",
                "pooled_mining_only",
                json!(only),
                json!(cfg.datum.pooled_mining_only),
            );
            if pool_host.is_empty() {
                match old_pool_host(edit.doc) {
                    Some(old) => {
                        edit.remove("datum", OLD_POOL_HOST);
                        edit.set("datum", "pool_host", json!(old));
                        pool_host = old;
                    }
                    None => {
                        edit.remove("datum", "pool_host");
                        edit.changed = true;
                        pool_host = default_host.clone();
                    }
                }
            }
        }
        Some("never") => {
            edit.set_if_changed(
                "datum",
                "pooled_mining_only",
                json!(false),
                json!(cfg.datum.pooled_mining_only),
            );
            if !pool_host.is_empty() {
                if let Some(named) = edit.doc.get("datum").and_then(|d| d.get("pool_host")).cloned()
                {
                    edit.set("datum", OLD_POOL_HOST, named);
                }
                edit.set("datum", "pool_host", json!(""));
                pool_host.clear();
            }
        }
        Some(_) => edit.errors.push("Reward sharing must be require, prefer or never".into()),
    }

    if let Some(host) = submitted(form, "datum_pool_host") {
        let host = host.trim();
        if !pool_host.is_empty() {
            edit.set_if_changed("datum", "pool_host", json!(host), json!(pool_host));
        } else if host != default_host || old_pool_host(edit.doc).is_some() {
            let old = old_pool_host(edit.doc).map_or(Value::Null, |o| json!(o));
            edit.set_if_changed("datum", OLD_POOL_HOST, json!(host), old);
        }
    }
}

fn apply_username_behaviour(edit: &mut Edit<'_>, cfg: &Config, form: &[(String, String)]) {
    match submitted(form, "username_behaviour") {
        None => {}
        Some("full_users") => edit.set_if_changed(
            "datum",
            "pool_pass_full_users",
            json!(true),
            json!(cfg.datum.pool_pass_full_users),
        ),
        Some(choice @ ("workers" | "private")) => {
            let workers = choice == "workers";
            edit.set_if_changed(
                "datum",
                "pool_pass_full_users",
                json!(false),
                json!(cfg.datum.pool_pass_full_users),
            );
            edit.set_if_changed(
                "datum",
                "pool_pass_workers",
                json!(workers),
                json!(cfg.datum.pool_pass_workers),
            );
        }
        Some(_) => {
            edit.errors.push("Miner usernames must be full_users, workers or private".into());
        }
    }
}

pub fn apply(
    cfg: &Config,
    file_text: &str,
    form: &[(String, String)],
) -> Result<Option<String>, Vec<String>> {
    let mut doc: Value = serde_json::from_str(file_text)
        .map_err(|e| vec![format!("the configuration file is not valid JSON: {e}")])?;
    let mut edit = Edit { doc: &mut doc, changed: false, errors: Vec::new() };

    apply_reward_sharing(&mut edit, cfg, form);
    apply_username_behaviour(&mut edit, cfg, form);

    for f in FIELDS {
        let Some(text) = submitted(form, f.name) else { continue };
        let current = (f.current)(cfg);
        match f.kind {
            FieldKind::Text => edit.set_if_changed(f.section, f.key, json!(text.trim()), current),
            FieldKind::RedactedUrl => {
                if json!(text.trim()) != current {
                    let original = edit
                        .doc
                        .get(f.section)
                        .and_then(|section| section.get(f.key))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let url = ratum::rpc::restore_redacted_password(text.trim(), &original);
                    edit.set(f.section, f.key, json!(url));
                }
            }
            FieldKind::Int { min, max } => match parse_int(f.label, text, min, max) {
                Ok(v) => edit.set_if_changed(f.section, f.key, json!(v), current),
                Err(e) => edit.errors.push(e),
            },
            FieldKind::Bool => match parse_bool(f.label, text) {
                Ok(v) => edit.set_if_changed(f.section, f.key, json!(v), current),
                Err(e) => edit.errors.push(e),
            },
            FieldKind::Password => {
                if !text.is_empty() {
                    edit.set(f.section, f.key, json!(text));
                }
            }
        }
    }

    if let Some(seconds) =
        submitted(form, "bitcoind_work_update_seconds").and_then(|t| t.trim().parse::<u64>().ok())
    {
        match seconds.checked_add(GLOBAL_TIMEOUT_MARGIN_SECS) {
            Some(needed) if cfg.datum.protocol_global_timeout < needed => {
                edit.set("datum", "protocol_global_timeout", json!(needed));
            }
            Some(_) => {}
            None => edit.errors.push(format!(
                "Job update interval {seconds} leaves no room for the pool timeout's \
                 {GLOBAL_TIMEOUT_MARGIN_SECS}-second margin"
            )),
        }
    }

    let Edit { changed, errors, .. } = edit;
    if !errors.is_empty() {
        return Err(errors);
    }
    if !changed {
        return Ok(None);
    }
    let text = render(&doc);
    let new = Config::parse(&text).map_err(|e| vec![e])?;
    check_startup(cfg, &new).map_err(|e| vec![e])?;
    Ok(Some(text))
}

/// The checks startup makes beyond `Config::parse`, each of which ends the gateway there, so a
/// saved file that fails one would stop the gateway at the restart the save causes: building
/// the node client, which reads the cookie file when no rpcuser is set, and binding the
/// stratum listener, checked here only when its address or port changed, since the running
/// gateway holds the current one.
fn check_startup(running: &Config, new: &Config) -> Result<(), String> {
    let b = &new.bitcoind;
    let cookie = (!b.rpccookiefile.is_empty()).then(|| PathBuf::from(&b.rpccookiefile));
    ratum::rpc::Client::new(&b.rpcurl, &b.rpcuser, &b.rpcpassword, cookie)
        .map_err(|e| format!("bitcoind: {e}"))?;
    let (was, s) = (&running.stratum, &new.stratum);
    if (was.listen_addr.as_str(), was.listen_port) != (s.listen_addr.as_str(), s.listen_port) {
        // The listener is dropped as soon as it is bound.
        ratum::net::bind_first(&s.listen_addr, s.listen_port, |a: &str| ratum::net::listen(a))
            .map_err(|e| format!("Stratum port {} cannot be opened: {e}", s.listen_port))?;
    }
    Ok(())
}

/// Replaces the configuration file with `text`. A symlink at `path` is resolved and its target
/// written, so the link is kept. The text is written to a new file beside the target, created
/// exclusively after removing anything already at that name (so a link there is never
/// followed) and, on unix, with the target's owner and group where the process may set them
/// (a warning names the file otherwise) and its permission bits whatever the umask; it is
/// synced, renamed over the target, and the directory synced so the rename is on disk.
pub fn write_file(path: &str, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let target = std::fs::canonicalize(path)?;
    let dir = target.parent().unwrap_or(Path::new("/")).to_path_buf();
    let mut tmp_name = target.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".new");
    let tmp = dir.join(tmp_name);
    let metadata = std::fs::metadata(&target)?;
    let permissions = metadata.permissions();
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        options.mode(permissions.mode() & 0o7777);
    }
    let written = options.open(&tmp).and_then(|mut file| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let (uid, gid) = (metadata.uid(), metadata.gid());
            if let Err(e) = std::os::unix::fs::fchown(&file, Some(uid), Some(gid)) {
                log::warn!(
                    "{}: could not keep its owner {uid} and group {gid} ({e}); the saved file \
                     is owned by this process's user",
                    target.display()
                );
            }
        }
        // The mode given at creation is reduced by the umask, and a change of owner can clear
        // the set-id bits; this sets it exactly.
        #[cfg(unix)]
        file.set_permissions(permissions)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, &target)?;
    #[cfg(unix)]
    std::fs::File::open(&dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::TcpListener;

    /// The `name` and the attribute `attr` of every `<input>` and `<select>` on the page.
    fn form_controls<'a>(html: &'a str, attr: &str) -> Vec<(&'a str, Option<&'a str>)> {
        let value = |tag: &'a str, key: &str| -> Option<&'a str> {
            let at = tag.find(&format!(" {key}=\""))? + key.len() + 3;
            let rest = &tag[at..];
            Some(&rest[..rest.find('"')?])
        };
        let mut out = Vec::new();
        let mut rest = html;
        while let Some(at) = rest.find('<') {
            rest = &rest[at + 1..];
            let Some(end) = rest.find('>') else { break };
            let (tag, after) = rest.split_at(end);
            rest = after;
            if !tag.starts_with("input ") && !tag.starts_with("select ") {
                continue;
            }
            if let Some(name) = value(tag, "name") {
                out.push((name, value(tag, attr)));
            }
        }
        out
    }

    /// The settings page's controls and `FIELDS` name the same configuration keys, with the
    /// same input types. A name in one and not the other fails silently at runtime: `apply`
    /// skips a submitted name `FIELDS` does not carry, and the page script skips a `FIELDS`
    /// entry with no element of that name, so the field renders as editable and never saves.
    #[test]
    fn every_control_on_the_settings_page_is_a_field_of_the_matching_type() {
        /// The controls the page handles on its own, outside `FIELDS`: the two selects, and
        /// the pool host that `apply_reward_sharing` parks and restores.
        const HANDLED_ON_THE_PAGE: [&str; 3] =
            ["datum_pool_host", "reward_sharing", "username_behaviour"];

        let controls = form_controls(include_str!("config.html"), "type");
        for f in FIELDS {
            let found = controls.iter().find(|(name, _)| *name == f.name);
            let Some((_, input_type)) = found else {
                panic!("{} is in FIELDS with no control on the settings page", f.name);
            };
            let want = match f.kind {
                FieldKind::Bool => Some("checkbox"),
                FieldKind::Password => Some("password"),
                FieldKind::Text | FieldKind::RedactedUrl | FieldKind::Int { .. } => None,
            };
            assert_eq!(*input_type, want, "{} has the wrong input type on the page", f.name);
        }
        for (name, _) in &controls {
            assert!(
                FIELDS.iter().any(|f| f.name == *name) || HANDLED_ON_THE_PAGE.contains(name),
                "the settings page has a control named {name} that FIELDS does not carry"
            );
        }
    }

    /// An integer field's `maxlength` must admit every value its range allows, or the browser
    /// truncates input the startup check would have accepted. The range is declared once, in
    /// `config.rs`; this is what keeps the page's attribute following it.
    #[test]
    fn an_integer_fields_maxlength_admits_its_whole_range() {
        let controls = form_controls(include_str!("config.html"), "maxlength");
        for f in FIELDS {
            let FieldKind::Int { max, .. } = f.kind else { continue };
            let Some((_, Some(maxlength))) = controls.iter().find(|(n, _)| *n == f.name) else {
                continue;
            };
            let digits = max.to_string().len();
            let allowed: usize = maxlength.parse().expect("maxlength is a number");
            assert!(
                allowed >= digits,
                "{}: maxlength {allowed} is shorter than the {digits} digits of its maximum {max}",
                f.name
            );
        }
    }
    const FILE: &str = r#"{
    "bitcoind": {"rpcuser": "u", "rpcpassword": "p", "rpcurl": "http://127.0.0.1:18443"},
    "mining": {"pool_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
    "datum": {"pool_host": "", "pooled_mining_only": false}
}"#;

    fn form(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn cfg() -> Config {
        Config::parse(FILE).unwrap()
    }

    #[test]
    fn unchanged_values_write_nothing() {
        let c = cfg();
        let f = form(&[
            ("mining_pool_address", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
            ("mining_coinbase_unique_id", "4242"),
            ("bitcoind_rpcpassword", ""),
            ("reward_sharing", "never"),
            ("username_behaviour", "full_users"),
            ("stratum_fingerprint_miners", "1"),
        ]);
        assert_eq!(apply(&c, FILE, &f).unwrap(), None);
    }

    #[test]
    fn edits_are_written_with_the_file_order_kept() {
        let c = cfg();
        let f = form(&[("mining_coinbase_unique_id", "7"), ("stratum_vardiff_min", "1024")]);
        let text = apply(&c, FILE, &f).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["mining"]["coinbase_unique_id"], 7);
        assert_eq!(doc["stratum"]["vardiff_min"], 1024);
        let keys: Vec<&str> = doc.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["bitcoind", "mining", "datum", "stratum"]);
        assert!(text.starts_with("{\n    \"bitcoind\""), "{text}");
    }

    #[test]
    fn the_startup_validation_refuses_a_bad_edit() {
        let c = cfg();
        let e = apply(&c, FILE, &form(&[("mining_pool_address", "nonsense")])).unwrap_err();
        assert!(e[0].contains("mining.pool_address"), "{e:?}");
        let e = apply(&c, FILE, &form(&[("mining_coinbase_unique_id", "70000")])).unwrap_err();
        assert_eq!(e, ["Unique gateway ID must be between 0 and 65535"]);
        let e = apply(&c, FILE, &form(&[("datum_pool_port", "x")])).unwrap_err();
        assert_eq!(e, ["Pool port must be a whole number"]);
        let e = apply(&c, FILE, &form(&[("stratum_max_network_share_bps", "20000")])).unwrap_err();
        assert_eq!(e, ["Network hashrate limit must be between 0 and 10000"]);
    }

    #[test]
    fn reward_sharing_parks_and_restores_the_pool_host() {
        let c = cfg();
        let text = apply(&c, FILE, &form(&[("datum_pool_host", "pool.example")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_host"], "");
        assert_eq!(doc["datum"]["pool_host(old)"], "pool.example");
        assert_eq!(form_values(&c, &doc)["datum_pool_host"], "pool.example");
        let default = DatumConfig::default().pool_host;
        assert_eq!(apply(&c, FILE, &form(&[("datum_pool_host", default.as_str())])).unwrap(), None);

        let key = "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003";
        let f = form(&[
            ("reward_sharing", "require"),
            ("datum_pool_host", "pool.example"),
            ("datum_pool_pubkey", key),
        ]);
        let text = apply(&c, &text, &f).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_host"], "pool.example");
        assert_eq!(doc["datum"]["pooled_mining_only"], true);
        assert!(doc["datum"].get("pool_host(old)").is_none());

        let pooled = Config::parse(&text).unwrap();
        let text = apply(&pooled, &text, &form(&[("reward_sharing", "never")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_host"], "");
        assert_eq!(doc["datum"]["pool_host(old)"], "pool.example");
        assert_eq!(doc["datum"]["pooled_mining_only"], false);
    }

    #[test]
    fn username_behaviour_sets_both_flags() {
        let c = cfg();
        let text = apply(&c, FILE, &form(&[("username_behaviour", "workers")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_pass_full_users"], false);
        assert!(doc["datum"].get("pool_pass_workers").is_none(), "the default is kept");
        let text = apply(&c, FILE, &form(&[("username_behaviour", "private")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_pass_full_users"], false);
        assert_eq!(doc["datum"]["pool_pass_workers"], false);
    }

    #[test]
    fn a_longer_job_interval_raises_the_pool_timeout() {
        let c = cfg();
        let text =
            apply(&c, FILE, &form(&[("bitcoind_work_update_seconds", "100")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["bitcoind"]["work_update_seconds"], 100);
        assert_eq!(doc["datum"]["protocol_global_timeout"], 105);
    }

    #[test]
    fn an_rpcurl_password_is_redacted_and_the_redacted_form_keeps_the_file_value() {
        let file = FILE.replace("http://127.0.0.1:18443", "http://rpc:secret@127.0.0.1:18443");
        let c = Config::parse(&file).unwrap();
        let shown = form_values(&c, &Value::Null);
        assert_eq!(shown["bitcoind_rpcurl"], "http://rpc:***@127.0.0.1:18443");
        let unchanged = form(&[("bitcoind_rpcurl", "http://rpc:***@127.0.0.1:18443")]);
        assert_eq!(apply(&c, &file, &unchanged).unwrap(), None, "the file's value is kept");
        let edited = form(&[("bitcoind_rpcurl", "http://rpc:other@127.0.0.1:18443")]);
        let text = apply(&c, &file, &edited).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["bitcoind"]["rpcurl"], "http://rpc:other@127.0.0.1:18443");
        let port_only = form(&[("bitcoind_rpcurl", "http://rpc:***@127.0.0.1:18444")]);
        let text = apply(&c, &file, &port_only).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            doc["bitcoind"]["rpcurl"], "http://rpc:secret@127.0.0.1:18444",
            "an edit of another part keeps the file's password"
        );
    }

    #[test]
    fn a_job_interval_too_large_to_add_the_margin_to_is_refused() {
        let c = cfg();
        let f = form(&[("bitcoind_work_update_seconds", &u64::MAX.to_string())]);
        let e = apply(&c, FILE, &f).unwrap_err();
        assert!(e.iter().any(|e| e.contains("leaves no room")), "{e:?}");
    }

    #[test]
    fn a_save_that_would_stop_the_gateway_at_startup_is_refused() {
        let c = cfg();
        let e = apply(&c, FILE, &form(&[("bitcoind_rpcurl", "127.0.0.1:18443")])).unwrap_err();
        assert!(e[0].contains("bitcoind.rpcurl"), "{e:?}");

        let missing = std::env::temp_dir().join(format!("ratum-no-cookie-{}", std::process::id()));
        let file = FILE.replace(
            r#""rpcuser": "u""#,
            &format!(r#""rpcuser": "u", "rpccookiefile": "{}""#, missing.display()),
        );
        let c = Config::parse(&file).unwrap();
        let e = apply(&c, &file, &form(&[("bitcoind_rpcuser", "")])).unwrap_err();
        assert!(e[0].starts_with("bitcoind:"), "an unreadable cookie file is refused: {e:?}");

        let file =
            FILE.replace(r#""datum":"#, r#""stratum": {"listen_addr": "127.0.0.1"}, "datum":"#);
        let c = Config::parse(&file).unwrap();
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = held.local_addr().unwrap().port().to_string();
        let e = apply(&c, &file, &form(&[("stratum_listen_port", &taken)])).unwrap_err();
        assert!(e[0].starts_with(&format!("Stratum port {taken} cannot be opened")), "{e:?}");
        drop(held);
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let text = apply(&c, &file, &form(&[("stratum_listen_port", &free.to_string())]));
        assert!(text.unwrap().is_some(), "a port that can be bound is written");
    }

    #[cfg(unix)]
    #[test]
    fn writing_keeps_the_mode_and_a_symlink_and_never_follows_a_link_at_the_temporary_name() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = std::env::temp_dir().join(format!("ratum-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("gateway.json");
        std::fs::write(&target, "old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.json");
        symlink(&target, &link).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, "untouched").unwrap();
        symlink(&elsewhere, dir.join("gateway.json.new")).unwrap();

        write_file(link.to_str().unwrap(), "new").unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the mode is kept whatever the umask");
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "untouched");
        assert!(!dir.join("gateway.json.new").exists());

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_file(target.to_str().unwrap(), "newer").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_password_is_never_shown_and_kept_when_blank() {
        let c = cfg();
        let shown = form_values(&c, &Value::Null);
        assert!(shown.get("bitcoind_rpcpassword").is_none());
        assert_eq!(shown["bitcoind_rpcuser"], "u");
        assert_eq!(shown["reward_sharing"], "never");
        let f = form(&[("bitcoind_rpcpassword", "new"), ("bitcoind_rpcuser", "u")]);
        let text = apply(&c, FILE, &f).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["bitcoind"]["rpcpassword"], "new");
    }
}
