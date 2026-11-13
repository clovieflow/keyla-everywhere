//! `keyla` — operator entry point. `up` runs the gateway in the foreground;
//! `status` and `doctor` probe a running or configured installation.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use keyla_config::{Env, ProcessEnv, resolve_bind_host, resolve_port};
use serde_json::{Value, json};

const HELP: &str = "\
keyla — Keyla Everywhere

Usage:
  keyla [up|serve]              Run the gateway in the foreground
  keyla start                   Start a detached gateway (pid + log in the data dir)
  keyla down                    Stop the detached gateway
  keyla restart                 Restart the detached gateway
  keyla logs [--lines N] [-f]   Tail or follow the detached gateway log
  keyla setup                   Create or repair .env with an encryption key
  keyla build                   Build dashboard and release binary (no install)
  keyla update [--no-restart]   Pull, build, install, and restart in a checkout
  keyla status [--url URL] [--json]  Check readiness
  keyla doctor [--json]         Check configuration, database, and migrations
  keyla open [--url URL]        Open the console in a browser
  keyla completion <shell>      Print bash, zsh, or fish completion
  keyla version [--json]        Print version
  keyla help                    Show this help
";

const BASH_COMPLETION: &str = r#"_keyla_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local commands="up serve start down restart logs setup build update status doctor open completion version help"
  COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
}
complete -F _keyla_complete keyla
"#;

const ZSH_COMPLETION: &str = r#"#compdef keyla
_keyla() {
  local -a commands
  commands=(up serve start down restart logs setup build update status doctor open completion version help)
  _describe 'command' commands
}
_keyla "$@"
"#;

const FISH_COMPLETION: &str = r#"complete -c keyla -f -a "up serve start down restart logs setup build update status doctor open completion version help"
complete -c keyla -n '__fish_seen_subcommand_from logs' -l lines -r
complete -c keyla -n '__fish_seen_subcommand_from logs' -s f -l follow
complete -c keyla -n '__fish_seen_subcommand_from status' -l json
complete -c keyla -n '__fish_seen_subcommand_from status' -l url -r
complete -c keyla -n '__fish_seen_subcommand_from doctor' -l json
complete -c keyla -n '__fish_seen_subcommand_from update' -l no-restart
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("up") {
        "up" | "serve" | "__serve" => keyla_gateway::server::run().await,
        "start" => start_detached(),
        "down" => stop_detached(),
        "restart" => {
            let _ = stop_detached();
            start_detached()
        }
        "logs" => tail_logs(&args[1..]).await,
        "setup" => setup_env(),
        "build" => build_command(&args[1..]),
        "update" => update_source(&args[1..]),
        "status" => status(&args[1..]).await,
        "doctor" => doctor(&args[1..]).await,
        "open" => open_console(&args[1..]),
        "completion" => completion(&args[1..]),
        "version" | "--version" | "-V" => version(&args[1..]),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}

fn console_base(url: Option<&str>) -> String {
    let env = ProcessEnv;
    url.map(str::to_owned).unwrap_or_else(|| {
        let mut host = resolve_bind_host(&env);
        if host == "0.0.0.0" || host == "::" || host == "[::]" {
            host = "127.0.0.1".to_owned();
        }
        format!("http://{host}:{}", resolve_port(&env).unwrap_or(12800))
    })
}

fn parse_json_flag(args: &[String]) -> anyhow::Result<bool> {
    let mut json = false;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            anyhow::bail!("unknown option: {arg}");
        }
    }
    Ok(json)
}

async fn status(args: &[String]) -> anyhow::Result<()> {
    let mut json_output = false;
    let mut url: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json_output = true;
                index += 1;
            }
            "--url" => {
                let Some(value) = args.get(index + 1) else {
                    anyhow::bail!("--url needs a value");
                };
                url = Some(value.clone());
                index += 2;
            }
            value if !value.starts_with('-') && url.is_none() => {
                url = Some(value.to_owned());
                index += 1;
            }
            value => anyhow::bail!("unknown option: {value}"),
        }
    }
    let base = console_base(url.as_deref());
    let endpoint = format!("{}/health/ready", base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    match client.get(&endpoint).send().await {
        Ok(response) => {
            let ok = response.status().is_success();
            let code = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            if json_output {
                println!(
                    "{}",
                    json!({
                        "ok": ok,
                        "endpoint": endpoint,
                        "status": code,
                        "body": body,
                    })
                );
            } else {
                println!("{endpoint} -> {code} {body}");
            }
            if !ok {
                std::process::exit(1);
            }
            Ok(())
        }
        Err(error) => {
            if json_output {
                println!(
                    "{}",
                    json!({
                        "ok": false,
                        "endpoint": endpoint,
                        "error": error.to_string(),
                    })
                );
            } else {
                eprintln!("{endpoint} unreachable: {error}");
            }
            std::process::exit(1);
        }
    }
}

async fn doctor(args: &[String]) -> anyhow::Result<()> {
    let json_output = parse_json_flag(args)?;
    let env = ProcessEnv;
    let database_configured = [
        "DATABASE_URL",
        "DATABASE_PRIVATE_URL",
        "DATABASE_PUBLIC_URL",
        "PGHOST",
    ]
    .iter()
    .any(|name| env.get(name).is_some_and(|value| !value.trim().is_empty()));
    let encryption_key_set = env
        .get("KEYLA_ENCRYPTION_KEY")
        .is_some_and(|value| !value.trim().is_empty());
    let dashboard_dist = keyla_config::resolve_dashboard_dist(&env);

    let mut database = json!({
        "configured": database_configured,
        "reachable": Value::Null,
        "migrations": Value::Null,
        "providers": Value::Null,
        "models": Value::Null,
    });
    let mut ok = database_configured && encryption_key_set;
    let mut connect_error: Option<String> = None;

    if database_configured {
        match keyla_db::connect_pool(&env).await {
            Ok(pool) => {
                let migrations = keyla_db::ledger_status_embedded(&pool)
                    .await
                    .unwrap_or(false);
                let providers: i64 = sqlx::query_scalar("SELECT count(*) FROM providers")
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(0);
                let models: i64 = sqlx::query_scalar("SELECT count(*) FROM models")
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(0);
                database["reachable"] = json!(true);
                database["migrations"] = json!(migrations);
                database["providers"] = json!(providers);
                database["models"] = json!(models);
                ok = ok && migrations;
            }
            Err(error) => {
                let message = error.to_string();
                database["reachable"] = json!(false);
                database["error"] = json!(&message);
                connect_error = Some(message);
                ok = false;
            }
        }
    }

    let report = json!({
        "ok": ok,
        "database": database,
        "encryption_key": if encryption_key_set { "set" } else { "missing" },
        "dashboard_dist": dashboard_dist,
    });

    if json_output {
        println!("{report}");
        return Ok(());
    }

    println!(
        "database: {}",
        if database_configured {
            if connect_error.is_some() {
                "unreachable"
            } else {
                "configured"
            }
        } else {
            "missing (DATABASE_URL/PGHOST)"
        }
    );
    if let Some(error) = connect_error {
        println!("database error: {error}");
    }
    println!(
        "encryption key: {}",
        if encryption_key_set { "set" } else { "missing" }
    );
    println!("dashboard dist: {dashboard_dist}");
    if let Some(object) = report.get("database") {
        if object.get("migrations").and_then(Value::as_bool) == Some(true) {
            println!("migrations: applied");
            let providers = object.get("providers").and_then(Value::as_i64).unwrap_or(0);
            let models = object.get("models").and_then(Value::as_i64).unwrap_or(0);
            println!("catalog: {providers} providers, {models} models");
        } else if object.get("reachable").and_then(Value::as_bool) == Some(true) {
            println!("migrations: pending");
        }
    }
    Ok(())
}

fn version(args: &[String]) -> anyhow::Result<()> {
    let json_output = parse_json_flag(args)?;
    if json_output {
        println!(
            "{}",
            json!({
                "name": "keyla",
                "version": env!("CARGO_PKG_VERSION"),
            })
        );
    } else {
        println!("keyla {}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}

fn data_dir() -> std::path::PathBuf {
    keyla_config::resolve_data_dir(&ProcessEnv)
}

fn pid_path() -> std::path::PathBuf {
    data_dir().join("keyla.pid")
}

fn log_path() -> std::path::PathBuf {
    data_dir().join("keyla.log")
}

fn running_pid() -> Option<u32> {
    let raw = std::fs::read_to_string(pid_path()).ok()?;
    let pid: u32 = raw.trim().parse().ok()?;
    // `kill -0` tests liveness without sending a signal.
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .ok()
        .filter(|status| status.success())
        .map(|_| pid)
}

fn start_detached() -> anyhow::Result<()> {
    if let Some(pid) = running_pid() {
        println!("keyla is already running (pid {pid})");
        return Ok(());
    }
    let directory = data_dir();
    std::fs::create_dir_all(&directory)?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())?;
    let executable = std::env::current_exe()?;
    let mut command = std::process::Command::new(executable);
    command
        .arg("__serve")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .env("KEYLA_DATA_DIR", &directory);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let child = command.spawn()?;
    std::fs::write(pid_path(), format!("{}\n", child.id()))?;
    println!("keyla started (pid {})", child.id());
    Ok(())
}

fn stop_detached() -> anyhow::Result<()> {
    let Some(pid) = running_pid() else {
        println!("keyla is not running");
        let _ = std::fs::remove_file(pid_path());
        return Ok(());
    };
    let signal = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    if !signal.success() {
        anyhow::bail!("could not signal pid {pid}");
    }
    for _ in 0..100 {
        if running_pid().is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = std::fs::remove_file(pid_path());
    println!("keyla stopped");
    Ok(())
}

fn print_log_tail(content: &str, lines: usize) {
    let collected: Vec<&str> = content.lines().collect();
    let start = collected.len().saturating_sub(lines);
    for line in &collected[start..] {
        println!("{line}");
    }
}

async fn tail_logs(args: &[String]) -> anyhow::Result<()> {
    let mut lines = 100usize;
    let mut follow = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--lines" => {
                let Some(value) = args.get(index + 1) else {
                    anyhow::bail!("--lines needs a value");
                };
                lines = value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--lines must be a positive integer"))?;
                index += 2;
            }
            "--follow" | "-f" => {
                follow = true;
                index += 1;
            }
            value => anyhow::bail!("unknown logs option: {value}"),
        }
    }

    let path = log_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    print_log_tail(&content, lines);
    if !follow {
        return Ok(());
    }

    let mut position = content.len();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let next = match std::fs::read_to_string(&path) {
            Ok(next) => next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => anyhow::bail!("cannot read {}: {error}", path.display()),
        };
        if next.len() < position {
            // The log was rotated or truncated.
            position = 0;
        }
        if next.len() > position {
            print!("{}", &next[position..]);
            std::io::stdout().flush()?;
            position = next.len();
        }
    }
}

fn generate_encryption_key() -> String {
    use base64::Engine;
    use std::io::Read;
    let mut bytes = [0u8; 32];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        if file.read_exact(&mut bytes).is_err() {
            bytes = [0u8; 32];
        }
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn setup_env() -> anyhow::Result<()> {
    let path = std::env::current_dir()?.join(".env");
    let example = std::env::current_dir()?.join(".env.example");
    let mut text = if path.exists() {
        std::fs::read_to_string(&path)?
    } else if example.exists() {
        std::fs::read_to_string(&example)?
    } else {
        String::new()
    };
    let key = generate_encryption_key();
    let has_key = text.lines().any(|line| {
        line.trim_start().starts_with("KEYLA_ENCRYPTION_KEY=")
            && line.len() > "KEYLA_ENCRYPTION_KEY=".len()
    });
    if has_key {
        println!(".env already has KEYLA_ENCRYPTION_KEY; leaving it unchanged");
        return Ok(());
    }
    if text
        .lines()
        .any(|line| line.trim_start().starts_with("KEYLA_ENCRYPTION_KEY="))
    {
        text = text
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("KEYLA_ENCRYPTION_KEY=") {
                    format!("KEYLA_ENCRYPTION_KEY={key}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
    } else {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("KEYLA_ENCRYPTION_KEY={key}\n"));
    }
    std::fs::write(&path, text)?;
    println!(
        "wrote {} with a generated KEYLA_ENCRYPTION_KEY",
        path.display()
    );
    println!("set DATABASE_URL (and optionally REDIS_URL) before starting the gateway");
    Ok(())
}

fn run_command(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|error| anyhow::anyhow!("cannot run {program}: {error}"))?;
    if !status.success() {
        anyhow::bail!("{program} {} failed", args.join(" "));
    }
    Ok(())
}

fn build_release() -> anyhow::Result<PathBuf> {
    if !Path::new("Cargo.toml").is_file() {
        anyhow::bail!("run `keyla build` from the repository root (Cargo.toml not found)");
    }
    if Path::new("dashboard").is_dir() {
        println!("building dashboard...");
        run_command("bun", &["install"])?;
        run_command("bun", &["run", "dashboard:build"])?;
    }
    println!("building release binary...");
    run_command(
        "cargo",
        &["build", "--release", "-p", "keyla-cli", "--bin", "keyla"],
    )?;
    let built = PathBuf::from("target/release/keyla");
    if !built.is_file() {
        anyhow::bail!("release binary was not produced at {}", built.display());
    }
    Ok(built)
}

fn build_command(args: &[String]) -> anyhow::Result<()> {
    if !args.is_empty() {
        anyhow::bail!("keyla build takes no arguments");
    }
    let built = build_release()?;
    println!("release binary: {}", built.display());
    Ok(())
}

fn install_release_binary() -> anyhow::Result<()> {
    let built = std::path::PathBuf::from("target/release/keyla");
    if !built.is_file() {
        anyhow::bail!("release binary was not produced at {}", built.display());
    }
    let current = std::env::current_exe()?;
    let same = match (built.canonicalize(), current.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    };
    if same {
        println!("installed binary: {}", current.display());
        return Ok(());
    }
    let staged = current.with_extension("update");
    std::fs::copy(&built, &staged).map_err(|error| {
        anyhow::anyhow!(
            "cannot replace {} (run with sufficient permissions, or install {} manually): {error}",
            current.display(),
            built.display()
        )
    })?;
    std::fs::rename(&staged, &current).map_err(|error| {
        anyhow::anyhow!(
            "cannot install {} over {}: {error}",
            built.display(),
            current.display()
        )
    })?;
    println!("installed binary: {}", current.display());
    Ok(())
}

fn open_console(args: &[String]) -> anyhow::Result<()> {
    let mut url: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--url" => {
                let Some(value) = args.get(index + 1) else {
                    anyhow::bail!("--url needs a value");
                };
                url = Some(value.clone());
                index += 2;
            }
            value if !value.starts_with('-') && url.is_none() => {
                url = Some(value.to_owned());
                index += 1;
            }
            value => anyhow::bail!("unknown open option: {value}"),
        }
    }
    let base = console_base(url.as_deref());
    let target = if base.trim_end_matches('/').ends_with("/console") {
        base
    } else {
        format!("{}/console", base.trim_end_matches('/'))
    };
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg(&target).status();
    #[cfg(target_os = "windows")]
    let status = std::process::Command::new("cmd")
        .args(["/C", "start", "", &target])
        .status();
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = std::process::Command::new("xdg-open").arg(&target).status();
    match status {
        Ok(status) if status.success() => {
            println!("opened {target}");
            Ok(())
        }
        Ok(_) => anyhow::bail!("browser opener failed for {target}"),
        Err(error) => anyhow::bail!("cannot open {target}: {error}"),
    }
}

fn completion(args: &[String]) -> anyhow::Result<()> {
    let Some(shell) = args.first() else {
        anyhow::bail!("usage: keyla completion <bash|zsh|fish>");
    };
    if args.len() != 1 {
        anyhow::bail!("usage: keyla completion <bash|zsh|fish>");
    }
    match shell.as_str() {
        "bash" => print!("{BASH_COMPLETION}"),
        "zsh" => print!("{ZSH_COMPLETION}"),
        "fish" => print!("{FISH_COMPLETION}"),
        other => anyhow::bail!("unsupported shell: {other} (use bash, zsh, or fish)"),
    }
    Ok(())
}

fn update_source(args: &[String]) -> anyhow::Result<()> {
    let restart = !args.iter().any(|arg| arg == "--no-restart");
    for arg in args {
        if arg != "--no-restart" {
            anyhow::bail!("unknown update option: {arg}");
        }
    }
    if !std::path::Path::new(".git").exists() {
        println!("this is not a source checkout; install the newest release binary");
        return Ok(());
    }

    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map_err(|error| anyhow::anyhow!("cannot run git: {error}"))?;
    if !dirty.status.success() {
        anyhow::bail!("git status failed");
    }
    if !dirty.stdout.is_empty() {
        anyhow::bail!("working tree is dirty; commit or stash changes before `keyla update`");
    }

    run_command("git", &["pull", "--ff-only"])?;
    build_release()?;
    install_release_binary()?;

    if restart && running_pid().is_some() {
        stop_detached()?;
        start_detached()?;
        println!("update complete; gateway restarted");
    } else if restart {
        println!("update complete; gateway is not running, start it with `keyla start`");
    } else {
        println!("update complete; restart skipped (--no-restart)");
    }
    Ok(())
}
