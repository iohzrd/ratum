use super::config::{
    Config, Datum, GLOBAL_TIMEOUT_MARGIN_SECS, MAX_CONFIGURED_TAG, MAX_CONFIGURED_TAGS_TOTAL,
    WORK_UPDATE_SECONDS_RANGE,
};
use serde_json::{Value, json};

const MAX_PORT: i64 = u16::MAX as i64;
const MAX_COINBASE_UNIQUE_ID: i64 = u16::MAX as i64;

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
    Int(i64, i64),
    Bool,
    Password,
}

const FIELDS: &[Field] = &[
    Field {
        name: "mining_pool_address",
        label: "Bitcoin address",
        section: "mining",
        key: "pool_address",
        kind: FieldKind::Text,
        current: |c| json!(c.mining.pool_address),
    },
    Field {
        name: "mining_coinbase_tag_secondary",
        label: "Coinbase tag",
        section: "mining",
        key: "coinbase_tag_secondary",
        kind: FieldKind::Text,
        current: |c| json!(c.mining.coinbase_tag_secondary),
    },
    Field {
        name: "mining_coinbase_unique_id",
        label: "Unique gateway ID",
        section: "mining",
        key: "coinbase_unique_id",
        kind: FieldKind::Int(0, MAX_COINBASE_UNIQUE_ID),
        current: |c| json!(c.mining.coinbase_unique_id),
    },
    Field {
        name: "datum_pool_port",
        label: "Pool port",
        section: "datum",
        key: "pool_port",
        kind: FieldKind::Int(1, MAX_PORT),
        current: |c| json!(c.datum.pool_port),
    },
    Field {
        name: "datum_pool_pubkey",
        label: "Pool public key",
        section: "datum",
        key: "pool_pubkey",
        kind: FieldKind::Text,
        current: |c| json!(c.datum.pool_pubkey),
    },
    Field {
        name: "datum_pool_url",
        label: "Pool web page",
        section: "datum",
        key: "pool_url",
        kind: FieldKind::Text,
        current: |c| json!(c.datum.pool_url),
    },
    Field {
        name: "datum_protocol_v3",
        label: "Version 3 protocol",
        section: "datum",
        key: "protocol_v3",
        kind: FieldKind::Bool,
        current: |c| json!(c.datum.protocol_v3),
    },
    Field {
        name: "datum_gateway_fee_bps",
        label: "Gateway fee",
        section: "datum",
        key: "gateway_fee_bps",
        kind: FieldKind::Int(0, ratum::BASIS_POINTS_PER_UNIT as i64),
        current: |c| json!(c.datum.gateway_fee_bps),
    },
    Field {
        name: "datum_gateway_fee_address",
        label: "Gateway fee address",
        section: "datum",
        key: "gateway_fee_address",
        kind: FieldKind::Text,
        current: |c| json!(c.datum.gateway_fee_address),
    },
    Field {
        name: "stratum_listen_port",
        label: "Stratum port",
        section: "stratum",
        key: "listen_port",
        kind: FieldKind::Int(1, MAX_PORT),
        current: |c| json!(c.stratum.listen_port),
    },
    Field {
        name: "stratum_vardiff_min",
        label: "Minimum difficulty",
        section: "stratum",
        key: "vardiff_min",
        kind: FieldKind::Int(1, i64::MAX),
        current: |c| json!(c.stratum.vardiff_min),
    },
    Field {
        name: "stratum_fingerprint_miners",
        label: "Fingerprint miners",
        section: "stratum",
        key: "fingerprint_miners",
        kind: FieldKind::Bool,
        current: |c| json!(c.stratum.fingerprint_miners),
    },
    Field {
        name: "stratum_require_address_username",
        label: "Require an address as the username",
        section: "stratum",
        key: "require_address_username",
        kind: FieldKind::Bool,
        current: |c| json!(c.stratum.require_address_username),
    },
    Field {
        name: "bitcoind_work_update_seconds",
        label: "Job update interval",
        section: "bitcoind",
        key: "work_update_seconds",
        kind: FieldKind::Int(
            *WORK_UPDATE_SECONDS_RANGE.start() as i64,
            *WORK_UPDATE_SECONDS_RANGE.end() as i64,
        ),
        current: |c| json!(c.bitcoind.work_update_seconds),
    },
    Field {
        name: "bitcoind_rpcurl",
        label: "bitcoind RPC URL",
        section: "bitcoind",
        key: "rpcurl",
        kind: FieldKind::Text,
        current: |c| json!(c.bitcoind.rpcurl),
    },
    Field {
        name: "bitcoind_rpcuser",
        label: "bitcoind RPC user",
        section: "bitcoind",
        key: "rpcuser",
        kind: FieldKind::Text,
        current: |c| json!(c.bitcoind.rpcuser),
    },
    Field {
        name: "bitcoind_rpcpassword",
        label: "bitcoind RPC password",
        section: "bitcoind",
        key: "rpcpassword",
        kind: FieldKind::Password,
        current: |_| Value::Null,
    },
];

const OLD_POOL_HOST: &str = "pool_host(old)";

fn shown_pool_host(cfg: &Config, doc: &Value) -> String {
    if !cfg.datum.pool_host.is_empty() {
        return cfg.datum.pool_host.clone();
    }
    old_pool_host(doc).unwrap_or_else(|| Datum::default().pool_host)
}

fn old_pool_host(doc: &Value) -> Option<String> {
    doc.get("datum")?.get(OLD_POOL_HOST)?.as_str().map(str::to_string)
}

fn secondary_tag_max(cfg: &Config) -> usize {
    MAX_CONFIGURED_TAGS_TOTAL
        .saturating_sub(cfg.mining.coinbase_tag_primary.len())
        .min(MAX_CONFIGURED_TAG)
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
    let default_host = Datum::default().pool_host;
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
            FieldKind::Int(min, max) => match parse_int(f.label, text, min, max) {
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
        && cfg.datum.protocol_global_timeout < seconds + GLOBAL_TIMEOUT_MARGIN_SECS
    {
        edit.set("datum", "protocol_global_timeout", json!(seconds + GLOBAL_TIMEOUT_MARGIN_SECS));
    }

    let Edit { changed, errors, .. } = edit;
    if !errors.is_empty() {
        return Err(errors);
    }
    if !changed {
        return Ok(None);
    }
    let text = render(&doc);
    Config::parse(&text).map_err(|e| vec![e])?;
    Ok(Some(text))
}

pub fn write_file(path: &str, text: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.new");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

pub fn restart() -> ! {
    log::info!("Restarting to apply the new configuration");
    log::logger().flush();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::env::args_os().next().map(Into::into).unwrap_or_default());
    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let e = cmd.exec();
        log::error!("Could not restart: {e}");
        log::logger().flush();
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        match cmd.spawn() {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                log::error!("Could not restart: {e}");
                log::logger().flush();
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
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
    }

    #[test]
    fn reward_sharing_parks_and_restores_the_pool_host() {
        let c = cfg();
        let text = apply(&c, FILE, &form(&[("datum_pool_host", "pool.example")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_host"], "");
        assert_eq!(doc["datum"]["pool_host(old)"], "pool.example");
        assert_eq!(form_values(&c, &doc)["datum_pool_host"], "pool.example");
        let default = Datum::default().pool_host;
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
