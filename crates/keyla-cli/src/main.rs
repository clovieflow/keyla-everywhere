//! `keyla` — operator entry point. `up` runs the gateway in the foreground;
//! `status` and `doctor` probe a running or configured installation.

use std::time::Duration;

use keyla_config::{Env, ProcessEnv, resolve_bind_host, resolve_port};

const HELP: &str = "\
keyla — Keyla Everywhere

Usage:
  keyla [up|serve|start]   Start the gateway in the foreground
  keyla start              Start a detached gateway (pid + log in the data dir)
  keyla down               Stop the detached gateway
  keyla restart            Restart the detached gateway
  keyla logs [--lines N]   Tail the detached gateway log
  keyla setup              Create or repair .env with an encryption key
  keyla update [--no-restart]  Pull, build, install, and restart in a checkout
  keyla status [--url URL] Check a running gateway's readiness
  keyla doctor             Check configuration, database, and migrations
  keyla version            Print version
  keyla help               Show this help
";

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
        "logs" => tail_logs(&args[1..]),
        "setup" => setup_env(),
        "update" => update_source(&args[1..]),
        "status" => status(args.get(1).map(String::as_str)).await,
        "doctor" => doctor().await,
        "version" | "--version" | "-V" => {
            println!("keyla {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
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

async fn status(url: Option<&str>) -> anyhow::Result<()> {
    let env = ProcessEnv;
    let base = url.map(str::to_owned).unwrap_or_else(|| {
        format!(
            "http://{}:{}",
            resolve_bind_host(&env),
            resolve_port(&env).unwrap_or(12800)
        )
    });
    let endpoint = format!("{}/health/ready", base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    match client.get(&endpoint).send().await {
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            println!("{endpoint} -> {status} {body}");
            if status.is_success() {
                Ok(())
            } else {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{endpoint} unreachable: {error}");
            std::process::exit(1);
        }
    }
}

async fn doctor() -> anyhow::Result<()> {
    let env = ProcessEnv;
    let database_configured = [
        "DATABASE_URL",
        "DATABASE_PRIVATE_URL",
        "DATABASE_PUBLIC_URL",
        "PGHOST",
    ]
    .iter()
    .any(|name| env.get(name).is_some_and(|value| !value.trim().is_empty()));
    println!(
        "database: {}",
        if database_configured {
            "configured"
        } else {
            "missing (DATABASE_URL/PGHOST)"
        }
    );
    println!(
        "encryption key: {}",
        if env.get("KEYLA_ENCRYPTION_KEY").is_some() {
            "set"
        } else {
            "missing"
        }
    );
    println!(
        "dashboard dist: {}",
        keyla_config::resolve_dashboard_dist(&env)
    );
    if database_configured {
        match keyla_db::connect_pool(&env).await {
            Ok(pool) => {
                let migrations = keyla_db::ledger_status_embedded(&pool)
                    .await
                    .unwrap_or(false);
                println!(
                    "migrations: {}",
                    if migrations { "applied" } else { "pending" }
                );
                let providers: i64 = sqlx::query_scalar("SELECT count(*) FROM providers")
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(0);
                let models: i64 = sqlx::query_scalar("SELECT count(*) FROM models")
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(0);
                println!("catalog: {providers} providers, {models} models");
            }
            Err(error) => println!("database: unreachable ({error})"),
        }
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

fn tail_logs(args: &[String]) -> anyhow::Result<()> {
    let mut lines = 100usize;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--lines" {
            if let Some(value) = args.get(index + 1).and_then(|value| value.parse().ok()) {
                lines = value;
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    let content = std::fs::read_to_string(log_path()).unwrap_or_default();
    let collected: Vec<&str> = content.lines().collect();
    let start = collected.len().saturating_sub(lines);
    for line in &collected[start..] {
        println!("{line}");
    }
    Ok(())
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
    if std::path::Path::new("dashboard").is_dir() {
        run_command("bun", &["install"])?;
        run_command("bun", &["run", "dashboard:build"])?;
    }
    run_command(
        "cargo",
        &["build", "--release", "-p", "keyla-cli", "--bin", "keyla"],
    )?;
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
