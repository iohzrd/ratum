//! What the pool does with its arguments before it opens a socket.
//!
//! Every one of these settings determines where money goes or how much a share is credited,
//! so the cases tested are the ones the pool must refuse rather than infer.

mod support;

use support::{FakeNode, Pool, PoolArgs, TempDir, printed, run_pool, script_for_address};

const SCRIPT: &str = "00141111111111111111111111111111111111111111";

fn args_with(extra: &[&str]) -> Vec<String> {
    // Every refusal below is about some other argument, so this baseline carries the two
    // the pool always requires. The URL is only parsed; no connection is opened to it.
    let mut argv: Vec<String> = vec![
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--payout-script".into(),
        SCRIPT.into(),
        "--rpc".into(),
        "http://127.0.0.1:1".into(),
    ];
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv
}

fn refuses(extra: &[&str], because: &str) {
    let argv = args_with(extra);
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = run_pool(&borrowed);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{extra:?} should be refused with exit code 2, output:\n{}",
        printed(&output)
    );
    let text = printed(&output);
    assert!(text.contains(because), "{extra:?}: expected {because:?} in:\n{text}");
}

/// The config file and the clap command line must not diverge: every setting the file may hold
/// must also be a command-line flag, or a setting written in a file has no way to be given on
/// the command line. clap rejects an unknown flag as an "unexpected argument"; this walks the
/// file's settings and checks clap accepts each as a known flag.
#[test]
fn every_file_setting_is_a_clap_flag() {
    for flag in ratum_prime::config::Config::flags() {
        let output = run_pool(&[flag.as_str(), "x"]);
        let text = printed(&output);
        assert!(
            !text.contains("unexpected argument"),
            "{flag} is a file setting but clap does not accept it as a flag:\n{text}"
        );
    }
}

#[test]
fn a_pool_without_a_payout_will_not_start() {
    let output = run_pool(&["--listen", "127.0.0.1:0", "--rpc", "http://127.0.0.1:1"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("--payout-address (or --payout-script) is required"));
}

#[test]
fn payout_address_and_payout_script_together_are_refused() {
    let output = run_pool(&[
        "--listen",
        "127.0.0.1:0",
        "--rpc",
        "http://127.0.0.1:1",
        "--payout-script",
        SCRIPT,
        "--payout-address",
        "bc1qexample",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("not both"));
}

#[test]
fn the_command_line_payout_overrides_the_one_in_the_file() {
    // The file names an address; the command line names a script. The command line takes
    // precedence, as it does for every other setting, rather than the two being refused as "not
    // both". The
    // command-line script is an OP_RETURN one refused by its own check, so a refusal naming
    // the script (not "not both") proves the script was taken and the file's address
    // discarded.
    let dir = TempDir::new("payout-override");
    std::fs::write(dir.join("ratum.toml"), "payout-address = \"bcrt1qexample\"\n").expect("toml");
    let output = run_pool(&[
        "--listen",
        "127.0.0.1:0",
        "--rpc",
        "http://127.0.0.1:1",
        "--data-dir",
        &dir.path().display().to_string(),
        "--payout-script",
        "6a0401020304",
    ]);
    let text = printed(&output);
    assert_eq!(output.status.code(), Some(2), "{text}");
    assert!(text.contains("OP_RETURN"), "the command-line script was validated: {text}");
    assert!(!text.contains("not both"), "the file address did not conflict with it: {text}");
}

#[test]
fn a_password_from_the_file_is_not_reported_as_on_the_command_line() {
    // A password in the config file is not visible in the process's command line, so the
    // command-line-password warning must not be emitted for it. With no payout the pool refuses and
    // exits after the point where that warning would have been emitted.
    let dir = TempDir::new("pass-in-file");
    std::fs::write(dir.join("ratum.toml"), "rpc-pass = \"hunter2\"\n").expect("toml");
    let output = run_pool(&[
        "--listen",
        "127.0.0.1:0",
        "--rpc",
        "http://127.0.0.1:1",
        "--data-dir",
        &dir.path().display().to_string(),
    ]);
    assert!(
        !printed(&output).contains("in this process's command line"),
        "a file password is not on the command line: {}",
        printed(&output)
    );

    // The same password on the command line is flagged.
    let output = run_pool(&[
        "--listen",
        "127.0.0.1:0",
        "--rpc",
        "http://127.0.0.1:1",
        "--rpc-pass",
        "hunter2",
    ]);
    assert!(
        printed(&output).contains("in this process's command line"),
        "a command-line password is flagged: {}",
        printed(&output)
    );
}

#[test]
fn a_pool_without_a_node_will_not_start() {
    // Without one the pool cannot resolve any miner's address, so it would credit shares
    // it can never pay and pay every block's coinbase to --payout-address.
    let output = run_pool(&["--listen", "127.0.0.1:0", "--payout-script", SCRIPT]);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("--rpc is required"));
}

#[test]
fn a_payout_script_too_long_for_a_coinbase_output_is_refused() {
    // Only the node checks this, and only at submitblock, so a longer script would be detected
    // only by every block the pool found being rejected after it was mined.
    refuses(&["--payout-script", &"ab".repeat(35)], "34 bytes");
}

#[test]
fn a_payout_script_at_the_limit_is_accepted() {
    // P2TR and P2WSH are exactly 34 bytes, so the limit has to admit them: refusing one
    // would turn a rule about invalid blocks into a rule against ordinary addresses.
    let p2tr = format!("5120{}", "ab".repeat(32));
    assert_eq!(p2tr.len() / 2, 34);
    let pool = Pool::start(
        TempDir::new("limit-p2tr"),
        PoolArgs { payout_script: Some(p2tr.clone()), ..Default::default() },
    );
    assert!(pool.expect_line("pool payout script:").contains(&p2tr));
}

#[test]
fn a_payout_script_that_burns_the_money_is_refused() {
    // Consensus allows 83 bytes of OP_RETURN, but this output receives every fallback
    // payment, so an OP_RETURN one destroys them rather than paying them.
    for script in [
        format!("6a{}", "cd".repeat(82)), // inside the 83-byte allowance
        "6a".to_string(),                 // bare
        "6a0100".to_string(),             // the gateway's zero-value filler script
    ] {
        refuses(&["--payout-script", &script], "OP_RETURN");
    }
}

#[test]
fn a_payout_script_must_be_non_empty_hex() {
    for bad in ["", "not hex", "abc"] {
        let output = run_pool(&[
            "--listen",
            "127.0.0.1:0",
            "--rpc",
            "http://127.0.0.1:1",
            "--payout-script",
            bad,
        ]);
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
        assert!(printed(&output).contains("non-empty hex script"), "{bad:?}");
    }
}

#[test]
fn a_difficulty_that_is_not_a_power_of_two_is_refused() {
    for bad in ["0", "3000", "-1", "", "many"] {
        refuses(&["--min-diff", bad], "must be a power of two");
    }
}

#[test]
fn numeric_flags_refuse_values_out_of_range_or_not_numbers() {
    refuses(&["--max-connections", "0"], "must be a positive number");
    refuses(&["--max-connections", "lots"], "must be a positive number");
    refuses(&["--prime-id", "-1"], "must be a number");
    refuses(&["--ledger-keep", "0"], "must be at least 1");
    refuses(&["--ledger-keep", "-1"], "must be at least 1");
    refuses(&["--ledger-keep", "some"], "must be at least 1");
    refuses(&["--min-payout", "some"], "count of satoshis");
    refuses(&["--window", "0"], "must be a positive number");
    refuses(&["--window", "-8"], "must be a positive number");
    refuses(&["--window", "nan"], "must be a positive number");
    refuses(&["--window-floor", "-1"], "sum of share difficulty");
    refuses(&["--activation-height", "soon"], "must be a block height");
}

#[test]
fn the_poll_interval_has_bounds() {
    refuses(&["--poll", "0"], "up to 3600");
    refuses(&["--poll", "-1"], "up to 3600");
    refuses(&["--poll", "3601"], "up to 3600");
    refuses(&["--poll", "forever"], "up to 3600");
}

#[test]
fn activation_height_and_headline_must_be_given_together() {
    refuses(&["--activation-height", "840000"], "must be given together");
    refuses(&["--headline", "a headline"], "must be given together");
}

#[test]
fn an_unknown_argument_is_not_ignored() {
    refuses(&["--rebroadcast"], "unexpected argument");
    refuses(&["-v"], "unexpected argument");
}

#[test]
fn a_flag_without_its_value_is_refused() {
    let output = run_pool(&["--listen"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("a value is required for '--listen"));
}

#[test]
fn a_cookie_file_must_hold_a_user_and_a_password() {
    let dir = TempDir::new("cookie");
    let missing = dir.join("nothing-here");
    let argv = args_with(&["--rpc-cookie", missing.to_str().unwrap()]);
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = run_pool(&borrowed);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("could not read the rpc cookie"));

    let malformed = dir.join("cookie");
    std::fs::write(&malformed, "no colon here").expect("write cookie");
    let argv = args_with(&["--rpc-cookie", malformed.to_str().unwrap()]);
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = run_pool(&borrowed);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("expected user:password"));
}

#[test]
fn a_cookie_file_is_read_instead_of_a_password_on_the_command_line() {
    let node = FakeNode::start();
    let dir = TempDir::new("cookie-ok");
    let cookie = dir.join("cookie");
    std::fs::write(&cookie, "__cookie__:5ecret\n").expect("write cookie");

    let pool = Pool::start(
        TempDir::new("cookie-ok-home"),
        PoolArgs {
            extra: vec![
                "--rpc".into(),
                node.url(),
                "--rpc-cookie".into(),
                cookie.display().to_string(),
            ],
            rpc_supplied_elsewhere: true,
            ..Default::default()
        },
    );
    pool.expect_line("watching the node");
    assert!(node.called("getblockchaininfo") > 0, "the pool reached the node with the cookie");
}

#[test]
fn an_address_the_node_accepts_becomes_the_payout_script() {
    let node = FakeNode::start();
    let pool = Pool::start(
        TempDir::new("payout-address"),
        PoolArgs {
            payout_script: None,
            payout_address: Some("bcrt1qexample".to_string()),
            rpc_url: Some(node.url()),
            ..Default::default()
        },
    );
    let line = pool.expect_line("pool payout script:");
    assert!(
        line.contains(&hex::encode(script_for_address("bcrt1qexample"))),
        "the script came from the node: {line}"
    );
}

#[test]
fn an_address_the_node_rejects_stops_the_pool() {
    let node = FakeNode::start();
    support::lock(&node.state).invalid_addresses.insert("nonsense".to_string());
    let argv = vec![
        "--listen".to_string(),
        "127.0.0.1:0".to_string(),
        "--payout-address".to_string(),
        "nonsense".to_string(),
        "--rpc".to_string(),
        node.url(),
        "--rpc-user".to_string(),
        "u".to_string(),
        "--rpc-pass".to_string(),
        "p".to_string(),
    ];
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = run_pool(&borrowed);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("is not an address this node accepts"));
}

#[test]
fn an_address_whose_script_is_too_long_for_a_coinbase_output_stops_the_pool() {
    // `validateaddress` accepts a future witness version and returns a scriptPubKey of up to
    // 42 bytes for it. That script is the coinbase remainder output, which cannot be left
    // out, so the gateway serves no work at all for as long as the node enforces the
    // reduced_data rule. Refusing it at startup names the flag instead.
    let node = FakeNode::start();
    support::lock(&node.state).oversized_addresses.insert("bcrt1future".to_string());
    let argv = vec![
        "--listen".to_string(),
        "127.0.0.1:0".to_string(),
        "--payout-address".to_string(),
        "bcrt1future".to_string(),
        "--rpc".to_string(),
        node.url(),
        "--rpc-user".to_string(),
        "u".to_string(),
        "--rpc-pass".to_string(),
        "p".to_string(),
    ];
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = run_pool(&borrowed);
    assert_eq!(output.status.code(), Some(2));
    let printed = printed(&output);
    assert!(printed.contains("--payout-address gives a 42-byte script"), "{printed}");
    assert!(printed.contains("34 bytes"), "{printed}");
}

#[test]
fn a_node_that_cannot_be_reached_stops_the_pool_before_it_listens() {
    // Port 1 on the loopback interface refuses connections.
    let output = run_pool(&[
        "--listen",
        "127.0.0.1:0",
        "--payout-address",
        "bc1qexample",
        "--rpc",
        "http://127.0.0.1:1",
        "--rpc-user",
        "u",
        "--rpc-pass",
        "p",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(printed(&output).contains("could not resolve --payout-address"));
}

#[test]
fn an_rpc_url_without_an_http_or_https_scheme_and_port_is_refused() {
    for bad in ["127.0.0.1:8332", "ftp://node:8332", "http://", "http://nohost"] {
        let argv = args_with(&["--rpc", bad]);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = run_pool(&borrowed);
        assert_ne!(output.status.code(), Some(0), "{bad:?} should not be accepted");
        assert!(printed(&output).contains("cannot parse RPC url"), "{bad:?}: {}", printed(&output));
    }
}

#[test]
fn the_settings_that_are_accepted_are_reported() {
    let pool = Pool::start(
        TempDir::new("reported"),
        PoolArgs {
            min_difficulty: 4096,
            min_payout: 25_000,
            window_multiple: 6.0,
            window_floor: 900,
            activation: Some((840_000, "a headline".to_string())),
            ..Default::default()
        },
    );
    let payouts = pool.expect_line("payouts:");
    assert!(payouts.contains("window 6x network difficulty"), "{payouts}");
    assert!(payouts.contains("floor 900"), "{payouts}");
    assert!(payouts.contains("minimum 25000 sats"), "{payouts}");
    let activation = pool.expect_line("activation:");
    assert!(activation.contains("height 840000"), "{activation}");
    assert!(activation.contains("a headline"), "{activation}");
}

/// A command line is readable by every other process on the machine, so a node password
/// given there is not a secret from anyone with a local account. The pool warns at startup.
#[test]
fn a_node_password_on_the_command_line_is_warned_about() {
    let node = support::FakeNode::start();
    let pool = support::Pool::start(
        support::TempDir::new("rpc-pass-argv"),
        support::PoolArgs {
            rpc_url: Some(node.url()),
            extra: vec!["--rpc-pass".into(), "hunter2".into()],
            ..Default::default()
        },
    );
    let line = pool.expect_line("--rpc-pass puts the node's password");
    assert!(line.contains("any local user can read it"), "{line}");
    assert!(line.contains("--rpc-cookie"), "it names what to use instead: {line}");
}

/// A cookie file is not on the command line, so no warning is emitted for it.
#[test]
fn a_password_kept_off_the_command_line_produces_no_warning() {
    let node = support::FakeNode::start();
    let dir = support::TempDir::new("rpc-pass-cookie");
    let cookie = dir.join("cookie");
    std::fs::write(&cookie, "__cookie__:5ecret\n").expect("write cookie");
    let pool = support::Pool::start(
        dir,
        support::PoolArgs {
            rpc_url: Some(node.url()),
            extra: vec!["--rpc-cookie".into(), cookie.display().to_string()],
            ..Default::default()
        },
    );
    pool.expect_line("listening on");
    assert!(
        !pool.lines().iter().any(|l| l.contains("--rpc-pass puts")),
        "no password was given on the command line"
    );
}

/// The configuration file the pool reads before its command line.
#[test]
fn settings_can_come_from_a_configuration_file() {
    let node = FakeNode::start();
    let dir = TempDir::new("config-file");
    let from_file = "0014".to_string() + &"ab".repeat(20);
    std::fs::write(
        dir.join("ratum.toml"),
        format!(
            "# where the money goes\npayout-script = \"{from_file}\"\n\nrpc = \"{}\"\n\
             rpc-user = \"test\"\nrpc-pass = \"test\"\n",
            node.url()
        ),
    )
    .expect("write the config");

    // Nothing here names a payout or a node; both come from the file.
    let pool = Pool::start(
        dir,
        PoolArgs { payout_script: None, rpc_supplied_elsewhere: true, ..Default::default() },
    );
    assert!(
        pool.expect_line("pool payout script:").contains(&from_file),
        "the file set the payout script"
    );
    assert!(node.called("getblockchaininfo") > 0, "and which node to watch");
}

/// A setting in both places takes the command line's value: the file supplies defaults.
#[test]
fn the_command_line_overrides_the_configuration_file() {
    let dir = TempDir::new("config-override");
    let from_file = "0014".to_string() + &"ab".repeat(20);
    let from_argv = "0014".to_string() + &"cd".repeat(20);
    std::fs::write(dir.join("ratum.toml"), format!("payout-script = \"{from_file}\"\n"))
        .expect("write the config");

    let pool =
        Pool::start(dir, PoolArgs { payout_script: Some(from_argv.clone()), ..Default::default() });
    let line = pool.expect_line("pool payout script:");
    assert!(line.contains(&from_argv), "the command line value is used: {line}");
    assert!(!line.contains(&from_file), "{line}");
}

/// A file the operator named and that is not there stops startup; a missing default file
/// does not.
#[test]
fn a_named_configuration_file_that_is_missing_stops_the_pool() {
    refuses(&["--config", "/nonexistent/ratum.toml"], "cannot read");
}

#[test]
fn a_configuration_file_that_does_not_parse_names_the_line() {
    let dir = TempDir::new("config-bad");
    let path = dir.join("ratum.toml");
    std::fs::write(&path, "motd = \"hi\"\nmin-diff = \n").expect("write");
    let out = run_pool(&[
        "--payout-script",
        &("0014".to_string() + &"ab".repeat(20)),
        "--config",
        &path.display().to_string(),
    ]);
    let text = printed(&out);
    assert!(text.contains("line 2"), "the place is named: {text}");
}

#[test]
fn a_configuration_file_cannot_name_another_one() {
    let dir = TempDir::new("config-recursive");
    let path = dir.join("ratum.toml");
    std::fs::write(&path, "config = \"/etc/other.toml\"\n").expect("write");
    let out = run_pool(&[
        "--payout-script",
        &("0014".to_string() + &"ab".repeat(20)),
        "--config",
        &path.display().to_string(),
    ]);
    // The same check that refuses any name the pool does not have.
    assert!(printed(&out).contains("config"), "{}", printed(&out));
}

/// A setting the pool does not have is caught by the same check a bad flag is, so the file
/// cannot hold an unrecognized name without a refusal.
#[test]
fn a_setting_the_pool_does_not_have_is_refused() {
    let dir = TempDir::new("config-unknown");
    let path = dir.join("ratum.toml");
    std::fs::write(&path, "min-diff = 4096\nnot-a-setting = 1\n").expect("write");
    let out = run_pool(&[
        "--payout-script",
        &("0014".to_string() + &"ab".repeat(20)),
        "--config",
        &path.display().to_string(),
    ]);
    assert!(printed(&out).contains("not-a-setting"), "{}", printed(&out));
}
