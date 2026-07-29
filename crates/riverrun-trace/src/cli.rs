//! The `riverrun` command line — one entry point, four verbs.
//!
//! Everything the measurement side of this repo does, behind a single binary with
//! sensible defaults, so a first run is `riverrun preflight <wallet>` and not a
//! hunt through six programs each with its own arguments.
//!
//! ```text
//! riverrun preflight <wallet> [pool] [n]   your anonymity before you act
//! riverrun audit     <pool> [n]            a live pool's true anonymity
//! riverrun trace     <wallet>              one wallet's funding provenance
//! riverrun exhibit                         the metric on riverrun's own designs
//! ```

use std::collections::HashSet;

use crate::rpc::{fee_payer, provenance_class, system_transfers, Rpc, HUB_THRESHOLD};
use crate::rng::SplitMix64;
use crate::runs::PRIVACY_CASH_N30;
use crate::uncertainty::{
    effective_k_interval, Bracket, Census, Gate, Interval, MemberOutcome, UnresolvedReason,
    DEFAULT_REPLICATES, DEFAULT_SEED,
};
use crate::{
    effective_k, evaluate, exposure_rank, preflight, scenario, valid_pubkey, EffectiveK,
    SchemeStats, Verdict,
};

/// Privacy Cash — a live Tornado-style SOL pool, the default when none is given.
const DEFAULT_POOL: &str = "9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD";

// bounded-trace parameters, shared by every command
const DEPTH: usize = 3;
const NODES: usize = 14;
const FUNDERS: usize = 4;
const SCAN_TX: usize = 6;
const POOL_SIG_SCAN: usize = 300;
const MIN_DEPOSIT: u64 = 10_000_000; // 0.01 SOL

// ---- color: TTY-aware, NO_COLOR-respecting, off for --json and pipes ----
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static USE_COLOR: AtomicBool = AtomicBool::new(false);

fn paint(code: &str, s: &str) -> String {
    if USE_COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}
fn red(s: &str) -> String { paint("1;31", s) }
fn green(s: &str) -> String { paint("1;32", s) }
fn yellow(s: &str) -> String { paint("1;33", s) }
fn cyan(s: &str) -> String { paint("36", s) }
fn dim(s: &str) -> String { paint("2", s) }

/// A severity or verdict word, uppercased and colored by risk: red for danger,
/// yellow for weak, green for safe. Color with intention (clig.dev).
fn paint_risk(word: &str) -> String {
    let up = word.to_uppercase();
    match word.to_ascii_lowercase().as_str() {
        "critical" | "high" | "exposed" => red(&up),
        "medium" | "weak" => yellow(&up),
        "low" | "ok" | "indistinguishable" => green(&up),
        _ => up,
    }
}

fn bold(s: &str) -> String { paint("1", s) }

/// Color an arbitrary string (a number, a phrase) by a severity level.
fn paint_by_sev(sev: &str, s: &str) -> String {
    match sev {
        "critical" | "high" => red(s),
        "medium" => yellow(s),
        _ => green(s),
    }
}

// ---- interactive, guided mode: anyone can use it, no commands, no hashes ----

/// Print a prompt and read one line from the user.
fn ask(prompt: &str) -> String {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    s.trim().to_string()
}

/// The default experience when you just run `riverrun`: a plain-language menu that
/// guides you, so you never need to know a command or paste a hash.
fn guide() {
    banner();
    status_rows();
    loop {
        println!("  {}", bold("What would you like to do?"));
        println!();
        println!("    {}   {}   {}", cyan("1"), bold("Become anonymous  "), dim("the step-by-step to disappear on Solana"));
        println!("    {}   {}   {}", cyan("2"), bold("Am I exposed?     "), dim("check your anonymity right now"));
        println!("    {}   {}   {}", cyan("3"), bold("Create an identity"), dim("one secret, a different face in every app"));
        println!("    {}   {}   {}", cyan("4"), bold("Measure a pool    "), dim("its real anonymity vs what it advertises"));
        println!();
        println!("    {}   {}   {}", dim("c"), dim("connect / disconnect"), dim("activate or clear your identity"));
        println!("    {}   {}", dim("q"), dim("quit"));
        println!();
        match ask(&format!("  {} ", cyan("›"))).as_str() {
            "1" => guided_anonymize(),
            "2" => guided_preflight(),
            "3" => guided_identity(),
            "4" => guided_audit(),
            "c" | "connect" => cmd_connect(),
            "d" | "disconnect" => cmd_disconnect(),
            "s" | "status" => cmd_status(),
            "q" | "quit" | "exit" | "" => {
                println!("  stay private.");
                break;
            }
            _ => println!("  {} type 1, 2, 3, 4, c, or q.", yellow("?")),
        }
        println!();
    }
}

/// The product: walk a person through actually becoming anonymous on Solana. The
/// mechanism is real and needs no unaudited pool: act from a fresh wallet funded from an
/// origin many others share, so the link from you to the action is broken and you are one
/// of a large crowd. riverrun measures where you start, picks the move, and verifies you
/// arrived. It never touches your keys and never moves your funds.
fn guided_anonymize() {
    println!();
    println!("  {}", bold("Become anonymous on Solana"));
    println!("  {}", dim("Break the link between you and what you do. Not hiding the transaction,"));
    println!("  {}", dim("hiding WHO did it. Four steps. riverrun never touches your keys."));
    println!();

    println!("  {}  {}", cyan("1"), bold("Where are you now?"));
    let w = ask(&format!("     {} the wallet you use today (or Enter to skip) › ", cyan("›")));
    if !w.is_empty() {
        cmd_preflight(std::slice::from_ref(&w), false);
    }
    println!();

    println!("  {}  {}", cyan("2"), bold("Use a fresh wallet for the sensitive action"));
    println!("     {}", dim("A new wallet with no history that ties it to you."));
    println!("     {}   {}", cyan("solana-keygen new -o fresh.json"), dim("(riverrun never sees your keys)"));
    println!();

    println!("  {}  {}", cyan("3"), bold("Fund it into a crowd"));
    println!("     {}", dim("Fund the fresh wallet from an origin many people share, so you blend in."));
    println!("     {}  {}", green("do   "), dim("withdraw to it from a major exchange: thousands share that origin"));
    println!("     {}  {}", red("avoid"), dim("funding it from your current wallet, that re-links you at once"));
    println!();

    println!("  {}  {}", cyan("4"), bold("Act, then verify you disappeared"));
    println!("     {}", dim("Do your action from the fresh wallet, then check your anonymity:"));
    let f = ask(&format!("     {} the fresh wallet, to verify (or Enter to skip) › ", cyan("›")));
    if !f.is_empty() {
        cmd_preflight(std::slice::from_ref(&f), false);
    }
    println!();
    println!("  {}  {}", green("✓"), dim("riverrun keeps watching and warns you if your crowd shrinks."));
    println!();
}

/// A tiny xorshift so the scramble varies per value, with no rand dependency.
fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

/// Watch a hash lock in: the bytes scramble and resolve left to right into the real
/// value. Honest, it resolves to the actual derived hash. Only animates on a terminal;
/// piped output just prints the result.
fn hash_anim(label: &str, target_hex: &str) {
    use std::io::Write;
    let show = 32.min(target_hex.len());
    let tgt = &target_hex[..show];
    if !USE_COLOR.load(Ordering::Relaxed) {
        println!("     {}  {}", label, tgt);
        return;
    }
    let hexc = b"0123456789abcdef";
    let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ target_hex.bytes().fold(0u64, |a, b| a.rotate_left(5) ^ b as u64);
    let frames = 16u32;
    for f in 0..=frames {
        let locked = (show as u32 * f / frames) as usize;
        let mut line = String::with_capacity(show);
        for (i, ch) in tgt.chars().enumerate() {
            if i < locked {
                line.push(ch);
            } else {
                line.push(hexc[(xorshift(&mut s) % 16) as usize] as char);
            }
        }
        let (lock, scr) = line.split_at(locked);
        print!("\r     {}  {}{}  {}", dim(label), cyan(lock), dim(scr), dim("hashing"));
        std::io::stdout().flush().ok();
        std::thread::sleep(std::time::Duration::from_millis(55));
    }
    println!("\r     {}  {}  {}        ", dim(label), bold(tgt), green("✓"));
}

/// Watch a 256-bit secret be generated: entropy fills in.
fn mint_anim(hex: &str) {
    use std::io::Write;
    if !USE_COLOR.load(Ordering::Relaxed) {
        return;
    }
    let hexc = b"0123456789abcdef";
    let mut s = 0xD1B5_4A32_D192_ED03u64 ^ hex.bytes().fold(0u64, |a, b| a.rotate_left(7) ^ b as u64);
    let show = 48.min(hex.len());
    let frames = 14u32;
    for f in 0..=frames {
        let locked = (show as u32 * f / frames) as usize;
        let mut line = String::with_capacity(show);
        for (i, ch) in hex[..show].chars().enumerate() {
            if i < locked {
                line.push(ch);
            } else {
                line.push(hexc[(xorshift(&mut s) % 16) as usize] as char);
            }
        }
        let (lock, scr) = line.split_at(locked);
        print!("\r     {}  {}{}", dim("entropy"), green(lock), dim(scr));
        std::io::stdout().flush().ok();
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    print!("\r{}\r", " ".repeat(70));
    std::io::stdout().flush().ok();
}

/// Guided: create a private identity, and see two contexts come out unlinkable.
fn guided_identity() {
    println!();
    println!("  {}", bold("Let's create your private identity."));
    println!("  {}", dim("One secret becomes a different, unlinkable identity in every app you use."));
    println!();
    let secret = riverrun_core::commitment::Secret::random();
    let hex = hex_encode(secret.as_bytes());
    println!("  {} {}", cyan("◈"), dim("generating a 256-bit post-quantum secret…"));
    mint_anim(&hex);
    println!("  {} your secret (write it down, it is your whole identity):", green("✓"));
    println!("      {}", bold(&hex));
    println!();
    let mut count = 0;
    loop {
        let prompt = if count == 0 {
            format!("  {} which app or place? (e.g. dao-vote, airdrop) › ", cyan("›"))
        } else {
            format!("  {} another one? (or press Enter to finish) › ", cyan("›"))
        };
        let ctx = ask(&prompt);
        if ctx.is_empty() {
            break;
        }
        let angle = context_angle(&ctx);
        let piece = secret.piece();
        let shape = hex_encode(&piece.shape(angle));
        let fit = hex_encode(&piece.fit(angle));
        println!();
        println!("  {} deriving your identity for {} …", cyan("◈"), cyan(&ctx));
        hash_anim("who you are (shape)", &shape);
        hash_anim("one action  (fit)  ", &fit);
        println!("     {}", dim("nobody can link these to you, or to your other apps."));
        count += 1;
        if count == 2 {
            println!();
            println!("  {} your two identities are completely different.", yellow("→"));
            println!("      {}", dim("that is the whole point: one secret, and no one can connect them to you."));
        }
    }
    println!();
}

/// Guided: check your anonymity in a pool before you act.
fn guided_preflight() {
    println!();
    println!("  {}", dim("Paste your wallet and I'll check the anonymity you would actually get."));
    let w = ask(&format!("  {} wallet › ", cyan("›")));
    if w.is_empty() {
        return;
    }
    println!();
    cmd_preflight(&[w], false);
}

// ---- session + protection panel (Tor-panel feel, honest about what it is) ----

fn session_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(std::path::Path::new(&home).join(".riverrun").join("session"))
}

/// The active identity secret, if one is connected on this machine.
fn load_session() -> Option<String> {
    let p = session_path()?;
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() == 64)
}

fn save_session(secret_hex: &str) -> std::io::Result<()> {
    let p = session_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no HOME"))?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&p, secret_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    // Windows has no chmod-equivalent bit; the file was otherwise saved with
    // whatever the parent directory's inherited ACL grants (other accounts on
    // a shared machine, by default), unlike Unix's 0600 above. Best-effort
    // lock it to the current user only via icacls (ships with every Windows
    // install, no extra dependency): strip inherited ACEs and grant Full
    // Control to $USERNAME alone. Failure here (e.g. icacls missing on some
    // non-standard Windows install) is not fatal; the session still saves,
    // just without this hardening, same as if this block did not exist.
    #[cfg(windows)]
    {
        if let Ok(user) = std::env::var("USERNAME") {
            let _ = std::process::Command::new("icacls")
                .arg(&p)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(format!("{user}:F"))
                .output();
        }
    }
    Ok(())
}

fn clear_session() {
    if let Some(p) = session_path() {
        let _ = std::fs::remove_file(p);
    }
}

/// The status panel: your privacy state at a glance, like a VPN or Tor panel, but
/// honest about what riverrun does. It does not tunnel your traffic. It makes your
/// actions unlinkable and measures how hidden you really are.
/// A dim, fixed-width label so the value columns line up. Padding is applied to the
/// plain text before coloring, so the alignment survives the ANSI codes.
fn label(s: &str) -> String {
    dim(&format!("{s:<13}"))
}

/// An elegant framed wordmark, top and bottom rules only, so it never misaligns.
fn header() {
    println!();
    println!("  {}", cyan("▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁"));
    println!("   {}   {}", bold(&cyan("riverrun")), dim("anonymity on Solana, post-quantum"));
    println!("  {}", cyan("▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔"));
}

/// The opening screen: a full teal wordmark, for `riverrun` with no arguments.
fn banner() {
    let art = [
        r"              ██",
        r"              ▀▀",
        r"  ██▄████   ████     ██▄  ▄██   ▄████▄    ██▄████   ██▄████  ██    ██  ██▄████▄",
        r"  ██▀         ██      ██  ██   ██▄▄▄▄██   ██▀       ██▀      ██    ██  ██▀   ██",
        r"  ██          ██      ▀█▄▄█▀   ██▀▀▀▀▀▀   ██        ██       ██    ██  ██    ██",
        r"  ██       ▄▄▄██▄▄▄    ████    ▀██▄▄▄▄█   ██        ██       ██▄▄▄███  ██    ██",
        r"  ▀▀       ▀▀▀▀▀▀▀▀     ▀▀       ▀▀▀▀▀    ▀▀        ▀▀        ▀▀▀▀ ▀▀  ▀▀    ▀▀",
    ];
    println!();
    for line in art {
        println!("  {}", cyan(line));
    }
    println!();
    println!("       {}", dim("anonymity on Solana   ·   post-quantum   ·   you can measure it"));
    println!("  {}", dim("──────────────────────────────────────────────────────────────────────────"));
}

/// The status rows: connection, post-quantum, identity, and how to measure.
fn status_rows() {
    let active = load_session();
    println!();
    match &active {
        Some(hex) => println!(
            "    {}  {}  {}  {}",
            green("●"),
            label("status"),
            green("connected"),
            dim(&format!("· {}…", &hex[..6]))
        ),
        None => println!(
            "    {}  {}  {}  {}",
            dim("○"),
            label("status"),
            dim("not connected"),
            dim(&format!("· run {}", cyan("riverrun connect")))
        ),
    }
    println!(
        "    {}  {}  {}  {}",
        green("●"),
        label("post-quantum"),
        "on, everlasting",
        dim(&format!("· {}", cyan("riverrun pq")))
    );
    println!("    {}  {}  {}", cyan("●"), label("identity"), dim("a different, unlinkable face in every app"));
    println!();
    println!("    {}  {}", label("measure yours"), cyan("riverrun preflight <wallet>"));
    println!();
}

fn cmd_status() {
    header();
    status_rows();
}

/// connect: activate a working identity on this machine.
fn cmd_connect() {
    if let Some(hex) = load_session() {
        println!();
        println!("  {} already connected ({}…). run `riverrun disconnect` to clear it.", green("●"), &hex[..8]);
        cmd_status();
        return;
    }
    let secret = riverrun_core::commitment::Secret::random();
    let hex = hex_encode(secret.as_bytes());
    match save_session(&hex) {
        Ok(()) => {
            println!();
            println!("  {} connected. a fresh identity is active on this machine.", green("●"));
            cmd_status();
        }
        Err(e) => {
            eprintln!("  {} could not save session: {e}", red("error"));
            std::process::exit(1);
        }
    }
}

/// disconnect: clear the active identity.
fn cmd_disconnect() {
    let had = load_session().is_some();
    clear_session();
    println!();
    if had {
        println!("  {} disconnected. the identity was cleared from this machine.", dim("○"));
    } else {
        println!("  {} nothing to disconnect. no identity was active.", dim("○"));
    }
    println!();
}

/// Guided: measure a pool's real anonymity.
fn guided_audit() {
    println!();
    let p = ask(&format!("  {} pool address (or Enter for the default) › ", cyan("›")));
    println!();
    if p.is_empty() {
        cmd_audit(&[], false);
    } else {
        cmd_audit(&[p], false);
    }
}

pub fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = take_flag(&mut args, "--json");
    let no_color = take_flag(&mut args, "--no-color");
    USE_COLOR.store(
        !json
            && !no_color
            && std::env::var_os("NO_COLOR").is_none()
            && (std::env::var_os("CLICOLOR_FORCE").is_some() || std::io::stdout().is_terminal()),
        Ordering::Relaxed,
    );
    if args.is_empty() {
        if std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
            guide();
        } else {
            help();
        }
        return;
    }
    let cmd = args[0].clone();
    let rest: &[String] = &args[1..];
    match cmd.as_str() {
        "guide" | "start" | "menu" => guide(),
        "status" => cmd_status(),
        "connect" => cmd_connect(),
        "disconnect" => cmd_disconnect(),
        "preflight" => cmd_preflight(rest, json),
        "audit" => cmd_audit(rest, json),
        "scan" => cmd_scan(rest, json),
        "watch" => cmd_watch(rest, json),
        "trace" => cmd_trace(rest, json),
        "exhibit" => cmd_exhibit(json),
        "runs" => cmd_runs(json),
        "id" => cmd_id(rest, json),
        "pq" | "quantum" => cmd_pq(rest),
        "floor" | "selffill" => cmd_floor(rest, json),
        "explain" | "learn" => cmd_explain(rest),
        "help" | "-h" | "--help" => help(),
        "version" | "-V" | "--version" => version(),
        other => {
            eprintln!("riverrun: unknown command '{other}'\n");
            help();
            std::process::exit(2);
        }
    }
}

/// Remove a `--flag` from the argument list wherever it appears, returning
/// whether it was present. Keeps positional parsing simple and order-free.
fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        args.remove(pos);
        true
    } else {
        false
    }
}

fn version() {
    println!("riverrun {}", env!("CARGO_PKG_VERSION"));
}

// --- pq: post-quantum posture + Mosca inequality ----------------------------

/// Expert-survey midpoint for a cryptographically-relevant quantum computer, in
/// years from now. An estimate, not a fact (Mosca's own framing): used only to
/// make the inequality concrete. Overridable as the second argument.
const QUANTUM_ETA_YEARS: u32 = 10;
/// Years to migrate a deployed system to quantum-safe crypto (the `Y` in Mosca).
const MIGRATION_YEARS: u32 = 2;

/// Mosca's inequality: you are safe iff the secret's required lifetime plus the
/// migration time fits inside the window before a quantum computer arrives.
/// `X + Y <= Z`. For a permanent ledger `X` is effectively infinite, so no
/// curve-based scheme can satisfy it.
fn mosca_safe(x_years: u32, y_years: u32, z_years: u32) -> bool {
    x_years.saturating_add(y_years) <= z_years
}

fn cmd_pq(args: &[String]) {
    // Optional: `riverrun pq <X> [Z]`, X = years your secret must stay secret,
    // Z = years until a quantum computer. Default X models a permanent ledger.
    let x_arg = args.first().and_then(|s| s.parse::<u32>().ok());
    let z = args.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(QUANTUM_ETA_YEARS);
    let y = MIGRATION_YEARS;

    println!("{}\n", cyan("riverrun: post-quantum posture"));
    println!("  {:<18}{:<22}{}", "primitive", "riverrun", "curve-based tools");
    println!("  {}", dim(&"-".repeat(58)));
    // pad the plain text to width first, then colorize, so ANSI codes do not
    // count toward the column width and the table stays aligned.
    let row = |k: &str, a: &str, b: &str|
        println!("  {:<18}{}{}", k, green(&format!("{a:<22}")), red(b));
    row("commitment", "BLAKE3 hash", "curve point");
    row("membership proof", "Rescue / FRI STARK", "Groth16 / BN254");
    row("trusted setup", "none", "ceremony (toxic waste)");
    row("under Shor", "nothing to break", "keys recovered");
    row("under Grover", "halved, absorbed", "n/a");

    println!("\n  {}  X + Y > Z  =>  you have already lost", yellow("Mosca's inequality:"));
    println!("    X = years your secret must stay secret");
    println!("    Y = years to migrate to quantum-safe crypto  (~{y})");
    println!("    Z = years until a quantum computer breaks today's curves  (~{z})");

    match x_arg {
        Some(x) => {
            let curve_safe = mosca_safe(x, y, z);
            println!(
                "\n  a curve-based tool, secret needed {x}y:  {}",
                if curve_safe { green("within the window") } else { red("EXPOSED (X+Y>Z)") }
            );
        }
        None => {
            println!(
                "\n  On a {}, X is effectively infinite: the chain is copied",
                yellow("permanent ledger")
            );
            println!("  forever, so any curve-based scheme fails the inequality.");
        }
    }
    println!(
        "\n  riverrun is hash-based: there is no curve for Shor to attack.\n  verdict: {}  what you hide today stays hidden after quantum.",
        green("POST-QUANTUM")
    );
}

// --- floor: the self-fill degradation ruler ---------------------------------

fn cmd_floor(args: &[String], json: bool) {
    let k: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(30);
    if k == 0 {
        eprintln!("usage: riverrun floor <k> [adversary_owned]");
        std::process::exit(2);
    }
    // If an adversary is named, report that one point; else print the curve.
    if let Some(a) = args.get(1).and_then(|s| s.parse::<usize>().ok()) {
        let h = k.saturating_sub(a);
        let ek = if h == 0 { 0.0 } else { effective_k(&[h]).effective };
        if json {
            println!(
                "{{\"advertised_k\":{k},\"adversary_owned\":{a},\"honest\":{h},\"effective_k\":{ek:.4}}}"
            );
        } else {
            println!(
                "advertised k {k}, adversary self-fills {a}  ->  honest {h}, effective-k {}",
                paint_by_sev(severity(ek, k, h), &format!("{ek:.1}"))
            );
        }
        return;
    }

    println!("{}\n", cyan("riverrun: the self-fill floor"));
    println!("  Advertised k is a ceiling, not a guarantee. If an adversary self-fills");
    println!("  `a` of the slots (a Sybil, or a whale funding many notes), the honest");
    println!("  set is k - a, and effective-k falls with it.\n");
    println!("  {:>14}   {:>12}   {:>12}", "adversary owns", "honest slots", "effective-k");
    println!("  {}", dim(&"-".repeat(44)));
    let picks: Vec<usize> = {
        let mut v: Vec<usize> = (0..k).filter(|a| a % (k / 5).max(1) == 0).collect();
        if *v.last().unwrap_or(&0) != k - 1 { v.push(k - 1); }
        v
    };
    for a in picks {
        let h = k - a;
        let ek = effective_k(&[h]).effective;
        let sev = severity(ek, k, h);
        println!(
            "  {:>14}   {:>12}   {}",
            a,
            h,
            paint_by_sev(sev, &format!("{:>12}", format!("{ek:.1}")))
        );
    }
    println!(
        "\n  Owning all but one leaves you {}. The defense is a per-participant\n  deposit cap and the funding-graph ruler, not a larger headline k.",
        red("alone")
    );
}

// --- explain: plain-language, because knowledge should be accessible --------

fn cmd_explain(args: &[String]) {
    let topic = args.first().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let body = match topic.as_str() {
        "effective-k" | "effective_k" | "k" =>
            "effective-k is your REAL anonymity, not the advertised crowd. A pool says\n\
             you are hidden among 30. But everyone's funding source is public, so an\n\
             adversary sorts the 30 by where their money came from. If your source is\n\
             yours alone, your real crowd is 1. effective-k = 2^(entropy of that\n\
             sorting): the size of the uniform crowd that would give the same doubt.",
        "self-fill" | "selffill" | "floor" =>
            "self-fill is how a whale or a Sybil shrinks your crowd. They submit their\n\
             own members into your round, and every slot they own is one they can\n\
             subtract, because they know it is theirs. Advertised k = 17 with 16\n\
             adversary slots is a crowd of 1. riverrun measures this floor. Try:\n\
             riverrun floor 30",
        "post-quantum" | "pq" | "quantum" =>
            "post-quantum means your privacy survives a quantum computer. Curve-based\n\
             tools (Groth16, ElGamal) are broken by Shor's algorithm, and a permanent\n\
             ledger lets an attacker copy your data today and crack it later. riverrun\n\
             stores only hashes, which Shor cannot break. Try: riverrun pq",
        "nullifier" =>
            "a nullifier is a one-time tag that lets you act exactly once without\n\
             revealing who you are. It is a hash of your secret and the round, so it\n\
             is unlinkable to you but unique, one vote or one claim per round, no\n\
             double-spend, no identity.",
        "provenance" | "trace" =>
            "provenance is where your money came from, traced backward on the public\n\
             chain. It is the quasi-identifier that survives a mixer: fresh wallet,\n\
             same funding source, same you. riverrun traces it so you can see your\n\
             exposure before you act. Try: riverrun trace <WALLET>",
        "riverrun-id" | "id" | "identity" =>
            "riverrun ID is one secret that becomes a different, unlinkable identity in\n\
             every context. One vote at the DAO, one claim at the airdrop, and nobody\n\
             can piece them back into you. It is Solana's missing Semaphore, and it is\n\
             post-quantum. Try: riverrun id new",
        _ => {
            println!("{}\n", cyan("riverrun explain: plain answers"));
            println!("  usage: riverrun explain <topic>\n\n  topics:");
            for t in ["effective-k", "self-fill", "post-quantum", "nullifier", "provenance", "riverrun-id"] {
                println!("    {}", green(t));
            }
            return;
        }
    };
    println!("{}\n", cyan(&format!("riverrun explain: {topic}")));
    for line in body.lines() {
        println!("  {line}");
    }
}

/// Reject a malformed address before spending any RPC calls: a typo would
/// otherwise come back empty and be misread as "rootless" / "no crowd".
fn require_pubkey(kind: &str, s: &str) {
    if !valid_pubkey(s) {
        eprintln!("riverrun: '{s}' is not a valid Solana {kind} (base58, 32 bytes).");
        std::process::exit(2);
    }
}

/// Map an anonymity result to a scanner-style severity, so `audit` reads like a
/// finding and not just a metric. `critical` when any member is alone in their
/// provenance class (fully de-anonymized), then by how far effective k has fallen
/// below the advertised set.
fn severity(effective: f64, advertised: usize, worst_case: usize) -> &'static str {
    if advertised == 0 {
        return "unknown";
    }
    if worst_case <= 1 {
        return "critical";
    }
    match effective / advertised as f64 {
        r if r < 0.5 => "high",
        r if r < 0.8 => "medium",
        _ => "low",
    }
}

/// One pool's measured funding-graph exposure. The unit `audit`, `scan`, and
/// `watch` all share — a measurement, never an inference.
struct PoolMeasurement {
    depositors_sampled: usize,
    reach_origin: usize,
    ek: EffectiveK,
    severity: &'static str,
    /// Every member accounted for: resolved, unresolved, or lost to our own RPC.
    census: Census,
    /// The two readings of the unresolved members. `ek` above is its upper end.
    bracket: Bracket,
    /// The spread of the upper reading over the draw of depositors.
    interval: Option<Interval>,
    /// Whether this sample supports quoting a single number at all.
    gate: Gate,
}

/// Measure a pool once: sample depositors, trace each one's provenance, and
/// reduce to effective k. `None` when no depositor crowd was recovered (so the
/// caller can tell "nothing to measure" from a real result). `verbose` prints the
/// per-depositor progress that `audit` wants and `scan`/`watch` do not.
fn measure_pool(
    rpc: &mut Rpc,
    pool: &str,
    n: usize,
    budget: &mut usize,
    verbose: bool,
) -> Option<PoolMeasurement> {
    let depositors = pool_depositors(rpc, pool, n, budget);
    if depositors.is_empty() {
        return None;
    }
    if verbose {
        eprintln!("tracing each one's funding graph...");
    }
    // Per-member outcomes, not just labels. A member whose trace hit an RPC
    // failure is recorded as ours and leaves the population: a throttled call
    // that returns nothing must never read as "this wallet has no funder", which
    // is exactly the bucket that inflates an anonymity figure.
    let mut outcomes: Vec<MemberOutcome> = Vec::with_capacity(depositors.len());
    let mut classes: Vec<String> = Vec::with_capacity(depositors.len());
    for (i, d) in depositors.iter().enumerate() {
        let failures_before = rpc.failures;
        let budget_before = *budget;
        let c = provenance_class(rpc, d, budget, DEPTH, NODES, FUNDERS, SCAN_TX);
        if verbose {
            eprintln!("  [{:>2}/{}] {}", i + 1, depositors.len(), short_class(&c));
        }
        let failed = rpc.failures > failures_before;
        let starved = budget_before > 0 && *budget == 0;
        let outcome = if c != "rootless" {
            MemberOutcome::Resolved { class: c.clone() }
        } else if failed {
            MemberOutcome::Unresolved { reason: UnresolvedReason::RpcFailure }
        } else if starved {
            MemberOutcome::Unresolved { reason: UnresolvedReason::TraceBudgetExhausted }
        } else {
            MemberOutcome::Unresolved { reason: UnresolvedReason::NoOriginWithinBound }
        };
        outcomes.push(outcome);
        classes.push(c);
    }

    let mut seen: Vec<(&String, usize)> = Vec::new();
    for c in &classes {
        if let Some(e) = seen.iter_mut().find(|(k, _)| *k == c) {
            e.1 += 1;
        } else {
            seen.push((c, 1));
        }
    }
    let reach_origin = classes.iter().filter(|c| *c != "rootless").count();
    let sizes: Vec<usize> = seen.iter().map(|(_, n)| *n).collect();
    let ek = effective_k(&sizes);
    let severity = severity(ek.effective, classes.len(), ek.worst_case);

    let census = Census::of(&outcomes);
    let bracket = Bracket::from_outcomes(&outcomes)?;
    let gate = bracket.gate(&census);
    // The interval is around the reading actually reported — the one where the
    // unresolved share a class — and it holds n fixed, so it is a statement about
    // this sample size only.
    let interval = effective_k_interval(&classes, DEFAULT_REPLICATES, DEFAULT_SEED);

    Some(PoolMeasurement {
        depositors_sampled: classes.len(),
        reach_origin,
        ek,
        severity,
        census,
        bracket,
        interval,
        gate,
    })
}

/// Exit cleanly when a live command recovered no data, distinguishing a genuine
/// empty result from an RPC that could not be reached — because for a privacy
/// tool a network failure must never be reported as "private".
fn no_data_exit(rpc: &Rpc, empty_reason: &str) -> ! {
    if rpc.failures > 0 {
        eprintln!(
            "\ncould not reach the RPC at {} ({} failed call(s)). Not reporting a\n\
             result: a network failure must never read as 'private'. Point $SOLANA_RPC\n\
             at a reliable endpoint and retry.",
            rpc.endpoint(),
            rpc.failures
        );
    } else {
        eprintln!("\n{empty_reason}");
    }
    std::process::exit(1);
}

fn help() {
    println!(
        "riverrun — measure and defend behavioural anonymity on Solana\n\
         \n\
         USAGE\n\
         \x20 riverrun <command> [args]\n\
         \n\
         COMMANDS\n\
         \x20 preflight <wallet> [pool] [n]   the anonymity YOU would get in a pool,\n\
         \x20                                 before you deposit — the one to run first\n\
         \x20 audit     <pool> [n]            a live pool's effective k vs its advertised k\n\
         \x20 scan      [pool...]             measure many pools, ranked by exposure (worst first)\n\
         \x20 watch     [pool...] [--interval s]  scan on a loop — the always-on screening agent\n\
         \x20 trace     <wallet>              one wallet's funding provenance, one hop at a time\n\
         \x20 exhibit                         the effective-k metric on riverrun's own\n\
         \x20                                 constructions (offline, no RPC)\n\
         \x20 runs                            this repo's published measurements, with their\n\
         \x20                                 bracket, interval and gate (offline, no RPC)\n\
         \x20 id <new|show|erosion>          riverrun ID: one secret, a different\n\
         \x20                                 unlinkable identity per context, offline\n\
         \x20 pq [X] [Z]                      post-quantum posture + Mosca inequality\n\
         \x20 floor <k> [adversary]          the self-fill floor: advertised k vs real\n\
         \x20 explain <topic>                plain answers (effective-k, post-quantum, ...)\n\
         \x20 version                         print the version and exit\n\
         \n\
         OPTIONS\n\
         \x20 --json                          emit a machine-readable JSON result on stdout\n\
         \x20                                 (progress stays on stderr; pipe with `| jq`)\n\
         \x20 --no-color                      disable color (also off when piped or NO_COLOR set)\n\
         \n\
         EXAMPLES\n\
         \x20 riverrun preflight <WALLET>           am I exposed in the default pool?\n\
         \x20 riverrun audit <POOL> 30              a pool's real anonymity, 30 samples\n\
         \x20 riverrun id new                       mint an identity secret\n\
         \x20 riverrun id show <SECRET> dao-vote    your unlinkable identity in one context\n\
         \x20 riverrun id erosion                   how a persistent identity erodes, when to rotate\n\
         \x20 riverrun audit <POOL> --json | jq     machine-readable, for scripts and CI\n\
         \n\
         DEFAULTS\n\
         \x20 pool  {DEFAULT_POOL}  (Privacy Cash)\n\
         \x20 n     15 depositors sampled\n\
         \x20 RPC   $SOLANA_RPC, else mainnet-beta\n\
         \n\
         Every result from live data is a floor: bounded trace, SOL flows only.\n\
         'safe' means 'no cheap attribution found', never 'anonymous'.\n\
         Exit codes: 0 ok, 1 no data (RPC / empty pool), 2 usage."
    );
}

// --- preflight --------------------------------------------------------------

fn cmd_preflight(args: &[String], json: bool) {
    let Some(wallet) = args.first() else {
        eprintln!("usage: riverrun preflight <wallet> [pool] [n]");
        std::process::exit(2);
    };
    let pool = args.get(1).map(String::as_str).unwrap_or(DEFAULT_POOL);
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15);
    require_pubkey("wallet", wallet);
    require_pubkey("pool", pool);

    let mut rpc = Rpc::new();
    let mut budget = 3000;

    eprintln!("wallet : {wallet}\npool   : {pool}\n\ntracing your funding graph backward...");
    let user_class = provenance_class(&mut rpc, wallet, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);
    eprintln!("  your provenance class: {}", describe(&user_class));

    eprintln!("\nsampling the pool's current depositors...");
    let depositors = pool_depositors(&mut rpc, pool, n, &mut budget);
    if depositors.is_empty() {
        no_data_exit(&rpc, "no recent SOL deposits found for this pool (inactive, or not a SOL pool).");
    }
    let population: Vec<String> = depositors
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let c = provenance_class(&mut rpc, d, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);
            eprintln!("  depositor {:>2}: {}", i + 1, short_class(&c));
            c
        })
        .collect();

    let p = preflight(&user_class, &population);

    if json {
        let verdict = match p.verdict {
            Verdict::Exposed => "exposed",
            Verdict::Weak => "weak",
            Verdict::Ok => "ok",
        };
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "preflight",
            "endpoint": rpc.endpoint(),
            "pool": pool,
            "wallet": wallet,
            "advertised_k": p.advertised_k,
            "pool_effective_k": p.pool_effective_k,
            "personal_k": p.personal_k,
            "verdict": verdict,
            "is_floor": true,
            "reliable": rpc.failures == 0,
            "rpc_calls": rpc.calls,
            "rpc_failures": rpc.failures,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== pre-flight anonymity check ===");
    println!("pool                   : {pool}");
    println!("advertised anonymity   : 1 in {}", p.advertised_k);
    println!("pool effective k (now) : {:.1}", p.pool_effective_k);
    println!("YOUR crowd here        : {} of {} share your provenance class", p.personal_k, p.advertised_k);
    print!("VERDICT                : ");
    match p.verdict {
        Verdict::Exposed => println!(
            "{}\n\nYou would be alone in your provenance class. The pool's size is\n\
             irrelevant to you: an adversary reading the funding graph attributes your\n\
             action at once. Fund a fresh wallet from a source other depositors also use\n\
             (a major exchange withdrawal is the usual one), or wait for a same-origin\n\
             crowd. Anonymity is a crowd of people who look like you, not a large crowd.",
            red("EXPOSED")
        ),
        Verdict::Weak => println!(
            "{}\n\nOnly {} of {} depositors share your provenance class, so your real\n\
             anonymity here is far below the advertised {}. Consider funding through a\n\
             more common origin, or waiting for a larger same-class crowd.",
            yellow("WEAK"), p.personal_k, p.advertised_k, p.advertised_k
        ),
        Verdict::Ok => println!(
            "{}\n\n{} of {} depositors share your provenance class,\n\
             a healthy fraction, so the crowd is genuinely yours. This is a floor: a deeper\n\
             trace can only shrink your class, so 'OK' means 'no cheap attribution found'.",
            green("OK (within the trace bound)"), p.personal_k, p.advertised_k
        ),
    }
    println!("\n(RPC calls: {})", rpc.calls);
}

// --- audit ------------------------------------------------------------------

fn cmd_audit(args: &[String], json: bool) {
    let pool = args.first().map(String::as_str).unwrap_or(DEFAULT_POOL);
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    require_pubkey("pool", pool);

    let mut rpc = Rpc::new();
    let mut budget = 4000;

    eprintln!("pool : {pool}\n\nenumerating depositors...");
    let Some(m) = measure_pool(&mut rpc, pool, n, &mut budget, true) else {
        no_data_exit(&rpc, "no depositors recovered: no recent SOL deposits (inactive, or not a SOL pool).");
    };
    let PoolMeasurement {
        depositors_sampled,
        reach_origin: rooted,
        ek,
        severity: sev,
        census,
        bracket,
        interval,
        gate,
    } = m;
    let classes_len = depositors_sampled;
    let refusal = match &gate {
        Gate::Publish => None,
        Gate::Refuse { reason } => Some(reason.clone()),
    };

    if json {
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "audit",
            "endpoint": rpc.endpoint(),
            "pool": pool,
            "severity": sev,
            "depositors_sampled": classes_len,
            "reach_origin": rooted,
            "reach_origin_pct": (100.0 * rooted as f64 / classes_len as f64),
            "provenance_classes": ek.classes,
            "advertised_k": classes_len,
            "effective_k": ek.effective,
            "worst_case": ek.worst_case,
            "residual_bits": ek.residual_bits,
            // the two readings of the members that reached no origin
            "effective_k_bracket": {
                "unresolved_merged": bracket.upper.effective,
                "unresolved_split": bracket.lower.effective,
                "resolved": bracket.resolved,
                "unresolved": bracket.unresolved,
                "resolved_fraction": bracket.resolved_fraction(),
            },
            "census": {
                "attempted": census.attempted(),
                "resolved": census.resolved,
                "no_origin_within_bound": census.no_origin_within_bound,
                "trace_budget_exhausted": census.trace_budget_exhausted,
                "rpc_failure": census.rpc_failure,
                "failure_rate": census.failure_rate(),
            },
            "sampling_interval": interval.map(|i| serde_json::json!({
                "statistic": "effective_k, unresolved merged",
                "point": i.point,
                "lo": i.lo,
                "hi": i.hi,
                "resampling_bias": i.resampling_bias(),
                "replicates": i.replicates,
                "seed": format!("{:#018x}", i.seed),
            })),
            "publishable": refusal.is_none(),
            "refusal": refusal,
            "is_floor": true,
            "reliable": rpc.failures == 0,
            "rpc_calls": rpc.calls,
            "rpc_failures": rpc.failures,
            "note": "floor: bounded trace, SOL-only; see docs/EFFECTIVE_K.md",
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== funding-graph exposure of a live anonymity set ===");
    println!("pool                   : {pool}");
    println!("severity               : {}", paint_risk(sev));
    println!("depositors sampled     : {classes_len}");
    println!("reach an origin        : {rooted}/{classes_len} ({:.0}%)", 100.0 * rooted as f64 / classes_len as f64);
    println!("provenance classes     : {}", ek.classes);
    println!(
        "advertised k           : {}  ->  effective k : {}  (worst case {})",
        classes_len,
        paint_by_sev(sev, &format!("{:.1}", ek.effective)),
        ek.worst_case
    );
    println!(
        "unresolved bracket     : {:.1} … {:.1}  ({} of {} reached an origin)",
        bracket.lower.effective,
        bracket.upper.effective,
        bracket.resolved,
        bracket.measured()
    );
    if let Some(i) = interval {
        println!(
            "95% resampling range   : {:.1} … {:.1}  (bias {:+.1}, {} replicates, seed {:#018x})",
            i.lo, i.hi, i.resampling_bias(), i.replicates, i.seed
        );
    }
    println!("census                 : {}", census.summary());
    match &refusal {
        Some(reason) => println!(
            "{}: {reason}\n\
             The effective k above is the favourable end of that bracket, not a result.",
            red("REFUSED")
        ),
        None => println!("gate                   : {}", green("PUBLISHABLE")),
    }
    println!(
        "\nAdvertised anonymity counts members. Effective k is what those members are\n\
         worth once an adversary sorts them by funding provenance — and members whose\n\
         bounded walk found no origin are a gap, not a class, which is what the bracket\n\
         spans. A floor: bounded trace, SOL only. See docs/EFFECTIVE_K.md."
    );
    if rpc.failures > 0 {
        println!("{}: {} RPC call(s) failed, this is a partial floor, not the full picture.", yellow("WARNING"), rpc.failures);
    }
    println!("(RPC calls: {}, failures: {})", rpc.calls, rpc.failures);
    // anticipate the next action (gh primer): send the reader to the personal check.
    println!("\n{}", dim(&format!("next: riverrun preflight <YOUR_WALLET> {pool}   (the anonymity YOU would get, before you deposit)")));
}

// --- scan / watch (the autonomous screening agent) --------------------------

/// Depositors sampled per pool in a multi-pool sweep — smaller than a single
/// `audit`, because breadth over many pools matters more than depth on one.
const SCAN_N: usize = 12;

/// Positional pool addresses from args, ignoring flags and the value that
/// follows `--interval`. Defaults to the built-in pool when none are given.
fn pools_from_args(args: &[String]) -> Vec<String> {
    let mut pools = Vec::new();
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--interval" {
            skip_next = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        pools.push(a.clone());
    }
    if pools.is_empty() {
        vec![DEFAULT_POOL.to_string()]
    } else {
        pools
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

/// Measure every pool, rank by exposure (worst first), and report. Unmeasured
/// pools are listed but never counted as private — a pool we could not reach or
/// that has no crowd is not a safe pool, it is an unknown one.
fn run_scan(pools: &[String], json: bool) {
    let mut rpc = Rpc::new();
    let mut ranked: Vec<(String, PoolMeasurement, usize)> = Vec::new();
    let mut unmeasured: Vec<(String, usize)> = Vec::new();
    for p in pools {
        eprintln!("scanning {p} ...");
        let f0 = rpc.failures;
        let mut budget = 2500;
        match measure_pool(&mut rpc, p, SCAN_N, &mut budget, false) {
            Some(m) => ranked.push((p.clone(), m, rpc.failures - f0)),
            None => unmeasured.push((p.clone(), rpc.failures - f0)),
        }
    }
    ranked.sort_by(|a, b| {
        exposure_rank(a.1.severity, a.1.ek.effective)
            .partial_cmp(&exposure_rank(b.1.severity, b.1.ek.effective))
            .unwrap()
    });

    if json {
        let rows: Vec<serde_json::Value> = ranked
            .iter()
            .enumerate()
            .map(|(i, (p, m, f))| {
                serde_json::json!({
                    "rank": i + 1,
                    "pool": p,
                    "severity": m.severity,
                    "advertised_k": m.depositors_sampled,
                    "effective_k": m.ek.effective,
                    "worst_case": m.ek.worst_case,
                    "reach_origin": m.reach_origin,
                    "effective_k_bracket": [m.bracket.lower.effective, m.bracket.upper.effective],
                    "publishable": m.gate.publishes(),
                    "reliable": *f == 0,
                    "rpc_failures": f,
                })
            })
            .collect();
        let un: Vec<serde_json::Value> = unmeasured
            .iter()
            .map(|(p, f)| {
                serde_json::json!({
                    "pool": p,
                    "measured": false,
                    "reason": if *f > 0 { "rpc_unreachable" } else { "no_deposit_crowd" },
                    "rpc_failures": f,
                })
            })
            .collect();
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "scan",
            "endpoint": rpc.endpoint(),
            "pools_scanned": pools.len(),
            "ranked": rows,
            "unmeasured": un,
            "is_floor": true,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== exposure ranking — most exposed first ===");
    println!("{:>2}  {:<8}  {:>7}  {:>5}  {:>5}  pool", "#", "severity", "eff-k", "adv-k", "worst");
    println!("{}", "-".repeat(74));
    for (i, (p, m, f)) in ranked.iter().enumerate() {
        let flag = if *f > 0 { "  (partial)" } else { "" };
        println!(
            "{:>2}  {:<8}  {:>7.1}  {:>5}  {:>5}  {}{}",
            i + 1, m.severity, m.ek.effective, m.depositors_sampled, m.ek.worst_case, p, flag
        );
    }
    for (p, f) in &unmeasured {
        let why = if *f > 0 { "RPC unreachable — NOT counted as private" } else { "no deposit crowd to measure" };
        println!(" -  {:<8}  {:>7}  {:>5}  {:>5}  {}  [{}]", "unknown", "-", "-", "-", p, why);
    }
    println!(
        "\nA floor: bounded, SOL-only traces. 'critical' = at least one member alone in its\n\
         provenance class. Unmeasured pools are unknown, never private."
    );
}

fn cmd_scan(args: &[String], json: bool) {
    let pools = pools_from_args(args);
    for p in &pools {
        require_pubkey("pool", p);
    }
    run_scan(&pools, json);
}

fn cmd_watch(args: &[String], json: bool) {
    let pools = pools_from_args(args);
    for p in &pools {
        require_pubkey("pool", p);
    }
    let interval: u64 = arg_value(args, "--interval").and_then(|s| s.parse().ok()).unwrap_or(300);
    eprintln!(
        "riverrun watch — screening {} pool(s) every {interval}s. Every pass is a fresh\n\
         measurement, never a cached inference. Ctrl-C to stop.",
        pools.len()
    );
    let mut pass = 1u64;
    loop {
        eprintln!("\n════ pass {pass} ════");
        run_scan(&pools, json);
        pass += 1;
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

// --- trace ------------------------------------------------------------------

fn cmd_trace(args: &[String], json: bool) {
    let Some(wallet) = args.first() else {
        eprintln!("usage: riverrun trace <wallet>");
        std::process::exit(2);
    };
    require_pubkey("wallet", wallet);
    let mut rpc = Rpc::new();
    let mut budget = 1500;

    eprintln!("wallet : {wallet}\n\ntracing backward funding graph over mainnet...");
    let class = provenance_class(&mut rpc, wallet, &mut budget, DEPTH, NODES, FUNDERS, SCAN_TX);

    if json {
        let rootless = class == "rootless";
        let hubs: Vec<String> = if rootless {
            Vec::new()
        } else {
            class.split('+').map(String::from).collect()
        };
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "trace",
            "endpoint": rpc.endpoint(),
            "wallet": wallet,
            "attributable_origin": !rootless,
            "hubs": hubs,
            "trace_depth": DEPTH,
            "is_floor": true,
            "reliable": rpc.failures == 0,
            "rpc_calls": rpc.calls,
            "rpc_failures": rpc.failures,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("\n=== provenance report ===");
    println!("wallet             : {wallet}");
    if class == "rootless" {
        println!("attributable origin: none within depth {DEPTH} (shallow, SOL-only trace)");
        println!(
            "\nAbsence here is the shallow bound, not proof of rootlessness — a deeper\n\
             trace or SPL-flow following may still reach an origin."
        );
    } else {
        println!("attributable origin: YES");
        for hub in class.split('+') {
            println!("    reaches hub {hub}");
        }
        println!(
            "\nThe funding graph leaks: a shallow, SOL-only backward walk already names\n\
             an attributable origin. This is the axis noise tools leave open."
        );
    }
    println!("(RPC calls: {})", rpc.calls);
}

// --- exhibit (offline) ------------------------------------------------------

// ---- id subcommand helpers ----

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// A context string becomes an angle by hashing, so a user names contexts by words
/// ("dao-vote", "airdrop") rather than numbers.
fn context_angle(context: &str) -> u64 {
    let h = blake3::hash(context.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// riverrun ID from the command line: one secret, a different unlinkable identity per
/// context, and the erosion ruler that says when to rotate.
fn cmd_id(args: &[String], json: bool) {
    match args.first().map(|s| s.as_str()).unwrap_or("help") {
        "new" => {
            let secret = riverrun_core::commitment::Secret::random();
            let hex = hex_encode(secret.as_bytes());
            if json {
                println!("{{\"tool\":\"riverrun\",\"command\":\"id new\",\"secret\":\"{hex}\"}}");
                return;
            }
            println!("your riverrun ID secret (keep it safe, it is your whole identity):");
            println!("  {hex}");
            println!();
            println!("one secret becomes a different, unlinkable identity in every context.");
            println!("try:  riverrun id show {} dao-vote", &hex[..16]);
        }
        "show" => {
            let (Some(sec_hex), Some(context)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: riverrun id show <secret-hex> <context>");
                std::process::exit(2);
            };
            let Some(bytes) = hex_decode_32(sec_hex) else {
                eprintln!("secret must be 64 hex chars (32 bytes). mint one with: riverrun id new");
                std::process::exit(2);
            };
            let secret = riverrun_core::commitment::Secret::from_bytes(bytes);
            let angle = context_angle(context);
            let piece = secret.piece();
            let shape = hex_encode(&piece.shape(angle));
            let fit = hex_encode(&piece.fit(angle));
            let turn = hex_encode(&piece.turn(angle));
            if json {
                println!("{{\"tool\":\"riverrun\",\"command\":\"id show\",\"context\":\"{context}\",\"angle\":{angle},\"shape\":\"{shape}\",\"fit\":\"{fit}\",\"turn\":\"{turn}\"}}");
                return;
            }
            println!("context: {}", cyan(context));
            println!("  {} : {shape}", dim("shape (your identity here)"));
            println!("  {} : {fit}", dim("fit   (your one action)   "));
            println!("  {} : {turn}", dim("turn  (continuity tag, ZK)"));
            println!();
            println!("the same secret in another context gives a different, unlinkable shape.");
        }
        "erosion" => {
            use crate::repeated::{repeated_use_effective_k, Use};
            // one persistent identity across three contexts; its crowd intersects down
            // 6 -> 3 -> 1 against a floor of 4.
            let uses = [Use::new(1, 0..6), Use::new(2, 0..3), Use::new(3, [0u32])];
            let e = repeated_use_effective_k(30, &uses, 4.0);
            if json {
                let keff: Vec<String> = e.k_eff.iter().map(|k| format!("{k}")).collect();
                let rot = e
                    .rotate_before
                    .map(|i| (i + 1).to_string())
                    .unwrap_or_else(|| "null".into());
                println!("{{\"tool\":\"riverrun\",\"command\":\"id erosion\",\"k_min\":4,\"k_eff\":[{}],\"rotate_before_use\":{rot}}}", keff.join(","));
                return;
            }
            println!("repeated-use erosion of one persistent identity (floor k_min = 4):");
            println!();
            for (i, k) in e.k_eff.iter().enumerate() {
                let below = *k < 4.0;
                let num = format!("{:>4.1}", k);
                let num = if below { red(&num) } else { green(&num) };
                let flag = if below { red("  <- below the floor") } else { String::new() };
                println!("  after use {}: effective anonymity = {}{}", i + 1, num, flag);
            }
            println!();
            match e.rotate_before {
                Some(i) => println!("{} before use {}: acting again under this secret drops you below the floor.", yellow("rotate (turn)"), i + 1),
                None => println!("{}: the identity stays above the floor across every use.", green("safe")),
            }
            println!("turn resets the secret; re-fund from a common origin to reset provenance too.");
        }
        _ => {
            println!("riverrun id — one secret, a different unlinkable identity per context\n");
            println!("USAGE");
            println!("  riverrun id new                       mint a fresh secret");
            println!("  riverrun id show <secret> <context>   your shape/fit/turn in a context");
            println!("  riverrun id erosion                   how a persistent identity erodes, when to rotate");
        }
    }
}

/// The runs this repository has published, re-measured offline with their
/// uncertainty attached. No RPC: it recomputes from the committed histogram, so
/// a reader gets the same bytes we did.
fn cmd_runs(json: bool) {
    let run = PRIVACY_CASH_N30;
    let b = run.bracket();
    let i = run.interval();
    let c = run.census();
    let refusal = match b.gate(&c) {
        Gate::Publish => None,
        Gate::Refuse { reason } => Some(reason),
    };

    if json {
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "runs",
            "offline": true,
            "runs": [{
                "source": run.source,
                "pool": run.pool,
                "sampled": run.sampled,
                "resolved": b.resolved,
                "unresolved": b.unresolved,
                "effective_k_bracket": {
                    "unresolved_merged": b.upper.effective,
                    "unresolved_split": b.lower.effective,
                },
                "sampling_interval": {
                    "statistic": "effective_k, unresolved merged",
                    "point": i.point,
                    "lo": i.lo,
                    "hi": i.hi,
                    "resampling_bias": i.resampling_bias(),
                    "replicates": i.replicates,
                    "seed": format!("{:#018x}", i.seed),
                },
                "publishable": refusal.is_none(),
                "refusal": refusal,
                "raw_sample_committed": false,
            }],
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    println!("{}\n", cyan("riverrun: the published runs, with what they do not know"));
    println!("  {} {}\n", dim("source:"), run.source);
    for line in run.report().lines() {
        println!("  {line}");
    }
    println!();
    for line in [
        "The class histogram is committed; the per-member addresses and funding edges",
        "were not recorded, so this recomputes the arithmetic, not the tracing.",
    ] {
        println!("  {}", dim(line));
    }
}

fn cmd_exhibit(json: bool) {
    const SEED: u64 = 0x000C_0FFE_ED15_EA5E;
    const N: usize = 2000;

    let mut rng = SplitMix64::new(SEED);
    let rows: [(&str, &str, SchemeStats); 3] = [
        ("rooted_decoy", "rooted decoy (the field)", evaluate(&scenario::rooted_decoy(&mut rng, N, 4))),
        ("cyclic_ambiguous", "cyclic, ambiguous root", evaluate(&scenario::cyclic_ambiguous(&mut rng, N, 60, 8))),
        ("cyclic_rootless", "cyclic, rootless", evaluate(&scenario::cyclic_rootless(&mut rng, N, 60))),
    ];

    if json {
        let constructions: Vec<serde_json::Value> = rows
            .iter()
            .map(|(id, _, s)| {
                serde_json::json!({
                    "construction": id,
                    "members": s.targets,
                    "root_hit_rate": s.root_hit_rate,
                    "mean_nearest_depth": if s.mean_nearest_depth.is_nan() { serde_json::Value::Null } else { serde_json::json!(s.mean_nearest_depth) },
                    "mean_attribution_bits": s.mean_attribution_bits,
                    "cyclic_rate": s.cyclic_rate,
                    "effective_k": s.effective_k.effective,
                })
            })
            .collect();
        let obj = serde_json::json!({
            "tool": "riverrun",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "exhibit",
            "offline": true,
            "members_per_row": N,
            "seed": format!("{SEED:#018x}"),
            "constructions": constructions,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        return;
    }

    let print_row = |name: &str, s: &SchemeStats| {
        let depth = if s.mean_nearest_depth.is_nan() {
            "  n/a".to_string()
        } else {
            format!("{:5.1}", s.mean_nearest_depth)
        };
        println!(
            "{:<26}  {:>11.1}%  {:>9}  {:>13.2}  {:>9.1}%  {:>11.0}",
            name, s.root_hit_rate * 100.0, depth, s.mean_attribution_bits, s.cyclic_rate * 100.0, s.effective_k.effective
        );
    };

    println!("the funding-graph leak every noise tool leaves open\n");
    println!(
        "{:<26}  {:>12}  {:>9}  {:>13}  {:>10}  {:>11}",
        "construction", "root-hit", "depth", "attrib.(bits)", "in-cycle", "effective k"
    );
    println!("{}", "-".repeat(92));
    for (_, label, s) in &rows {
        print_row(label, s);
    }
    println!(
        "\nSame {N} members each row. The field's decoys still trace to one origin\n\
         (root-hit ~100%, 0 bits of doubt); circularity dissolves it — a root that\n\
         could be any of many, or none at all — worth the full set instead of a\n\
         fraction. 'rootless' holds only while funding sources are unattributable."
    );
}

// --- shared helpers ---------------------------------------------------------

fn describe(class: &str) -> String {
    if class == "rootless" {
        "rootless (no attributable origin found within the trace bound)".to_string()
    } else {
        format!("reaches {}", short_class(class))
    }
}

fn short_class(c: &str) -> String {
    if c == "rootless" {
        return "rootless".to_string();
    }
    c.split('+').map(|a| format!("{}…", &a[..8.min(a.len())])).collect::<Vec<_>>().join("+")
}

/// Distinct non-hub fee payers who moved SOL into the pool recently.
fn pool_depositors(rpc: &mut Rpc, pool: &str, want: usize, budget: &mut usize) -> Vec<String> {
    pool_depositors_min(rpc, pool, want, budget, MIN_DEPOSIT)
}

/// Like `pool_depositors`, but with an explicit deposit floor instead of the
/// default `MIN_DEPOSIT`. Pools have different entry-fee denominations (a live
/// mixer's SOL floor is not a fresh test pool's much smaller entry fee), so a
/// caller measuring a specific pool's own commitment size passes it here rather
/// than tuning the shared `MIN_DEPOSIT` constant, which stays as the general
/// noise floor for `audit`/`preflight`/`scan`/`watch` against pools of unknown
/// denomination.
fn pool_depositors_min(
    rpc: &mut Rpc,
    pool: &str,
    want: usize,
    budget: &mut usize,
    min_deposit: u64,
) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for sig in rpc.signatures(pool, POOL_SIG_SCAN) {
        if out.len() >= want || *budget == 0 {
            break;
        }
        *budget -= 1;
        let Some(tx) = rpc.transaction(&sig) else { continue };
        let Some(payer) = fee_payer(&tx) else { continue };
        if seen.contains(&payer) {
            continue;
        }
        let deposits = system_transfers(&tx)
            .into_iter()
            .any(|(src, dst, l)| src == payer && dst != payer && l >= min_deposit);
        if !deposits {
            continue;
        }
        seen.insert(payer.clone());
        if rpc.sig_count(&payer) >= HUB_THRESHOLD {
            continue; // relayer / exchange, not a user
        }
        out.push(payer);
    }
    out
}

/// Measure a pool's real effective-k, for a caller (like the `act()` SDK
/// backend) that knows the pool's own deposit denomination rather than relying
/// on the general-purpose `MIN_DEPOSIT` noise floor. `None` when no depositors
/// were recovered (empty pool, wrong denomination, or the RPC could not be
/// reached). The caller must not treat that as "anonymous", only as
/// "unmeasured".
pub fn measure_pool_ruler(
    rpc: &mut Rpc,
    pool: &str,
    n: usize,
    budget: &mut usize,
    min_deposit: u64,
) -> Option<EffectiveK> {
    let depositors = pool_depositors_min(rpc, pool, n, budget, min_deposit);
    if depositors.is_empty() {
        return None;
    }
    let classes: Vec<String> = depositors
        .iter()
        .map(|d| provenance_class(rpc, d, budget, DEPTH, NODES, FUNDERS, SCAN_TX))
        .collect();
    let mut seen: Vec<(&String, usize)> = Vec::new();
    for c in &classes {
        if let Some(e) = seen.iter_mut().find(|(k, _)| *k == c) {
            e.1 += 1;
        } else {
            seen.push((c, 1));
        }
    }
    let sizes: Vec<usize> = seen.iter().map(|(_, n)| *n).collect();
    Some(effective_k(&sizes))
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn mosca_safe_only_when_lifetime_plus_migration_fits_before_quantum() {
        assert!(mosca_safe(3, 2, 10), "3+2=5 <= 10 is safe");
        assert!(mosca_safe(8, 2, 10), "8+2=10 <= 10 is exactly safe");
        assert!(!mosca_safe(9, 2, 10), "9+2=11 > 10 is exposed");
        // a permanent ledger: X is effectively infinite, so never safe for a
        // scheme that has to migrate. This is why hash-based must be the default.
        assert!(!mosca_safe(u32::MAX, 2, 10));
    }

    #[test]
    fn the_self_fill_floor_collapses_to_one_and_tops_out_at_the_crowd() {
        // one honest slot left is effective-k 1 (fully exposed)
        assert!((effective_k(&[1]).effective - 1.0).abs() < 1e-9);
        // the full untouched crowd is worth its size
        assert!((effective_k(&[30]).effective - 30.0).abs() < 1e-9);
    }
}
