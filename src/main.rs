use clap::{Parser, Subcommand, ValueEnum};
use network_exposure_policy_checker::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Parser)]
#[command(
    name = "network-exposure-policy-checker",
    version,
    about = "Declare intended network reachability. Detect unintended exposure."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    Init {
        #[arg(long)]
        compose: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    Inspect {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        config_only: bool,
    },
    Plan {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Probe {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        vantage: Zone,
        #[arg(long, default_value = "operator-declared")]
        source_id: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = 1500)]
        timeout: u64,
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
    },
    Audit {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        evidence: Vec<PathBuf>,
        #[arg(long,value_enum,default_value_t=Format::Human)]
        format: Format,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        fail_on: Option<Severity>,
        #[arg(long, value_delimiter = ',')]
        require_vantage: Vec<Zone>,
        #[arg(long, default_value_t = 24)]
        max_age_hours: i64,
    },
    Explain {
        rule: String,
    },
    Doctor,
}
#[derive(Subcommand)]
enum PolicyCmd {
    Validate {
        #[arg(long)]
        file: PathBuf,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
}
#[derive(Clone, Copy, ValueEnum)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}
fn read<T: DeserializeOwned>(p: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&std::fs::read(p)?)?)
}
fn write<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    std::fs::write(p, serde_json::to_vec_pretty(v)?)?;
    Ok(())
}
fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Policy {
            command: PolicyCmd::Validate { file },
        } => {
            let p = Policy::load(&file)?;
            println!(
                "Valid policy: {} ({} services)",
                p.project.name,
                p.services.len()
            );
            Ok(0)
        }
        Cmd::Init { compose, output } => {
            let raw = std::process::Command::new("docker")
                .args([
                    "compose",
                    "-f",
                    compose.to_str().unwrap_or(""),
                    "config",
                    "--format",
                    "json",
                ])
                .output()
                .map_err(|e| Error::Docker(e.to_string()))?;
            if !raw.status.success() {
                return Err(Error::Docker(String::from_utf8_lossy(&raw.stderr).into()));
            }
            let v: serde_json::Value = serde_json::from_slice(&raw.stdout)?;
            let mut text=String::from("# DRAFT: replace every REVIEW value with allow or deny before validation.\nversion: 1\nproject:\n  name: deployment\n  compose_files:\n");
            text.push_str(&format!(
                "    - {}\ntargets:\n  local:\n    addresses: [127.0.0.1]\nservices:\n",
                compose.display()
            ));
            if let Some(services) = v.get("services").and_then(|x| x.as_object()) {
                for (name, svc) in services {
                    text.push_str(&format!("  - name: {name}\n    compose_service: {name}\n    sensitivity: normal\n    endpoints:\n"));
                    let ports = svc.get("ports").and_then(|x| x.as_array());
                    if let Some(ports) = ports {
                        for (i, p) in ports.iter().enumerate() {
                            let cp = p.get("target").and_then(|x| x.as_u64()).unwrap_or(0);
                            let hp = p
                                .get("published")
                                .and_then(|x| x.as_str())
                                .unwrap_or("auto");
                            text.push_str(&format!("      - name: endpoint-{}\n        container_port: {}\n        host_port: {}\n        protocol: tcp\n        access:\n          local: REVIEW\n          lan: REVIEW\n          vpn: REVIEW\n          internet: REVIEW\n",i+1,cp,hp));
                        }
                    } else {
                        text.push_str("      []\n")
                    }
                }
            }
            std::fs::write(&output, text)?;
            println!(
                "Wrote draft {}. Review every access decision.",
                output.display()
            );
            Ok(0)
        }
        Cmd::Inspect {
            policy,
            output,
            config_only,
        } => {
            let p = Policy::load(&policy)?;
            let base = policy.parent().unwrap_or(Path::new("."));
            let s = inspect(&p, base, config_only)?;
            write(&output, &s)?;
            println!(
                "Snapshot {}: {} bindings, runtime {}",
                s.id,
                s.bindings.len(),
                if s.runtime_available {
                    "inspected"
                } else {
                    "not inspected"
                }
            );
            Ok(0)
        }
        Cmd::Plan {
            policy,
            snapshot,
            output,
        } => {
            let p = Policy::load(&policy)?;
            let s = read(&snapshot)?;
            let plan = plan(&p, &s)?;
            write(&output, &plan)?;
            println!("Plan {}: {} exact targets", plan.id, plan.targets.len());
            Ok(0)
        }
        Cmd::Probe {
            plan: plan_file,
            vantage,
            source_id,
            output,
            dry_run,
            timeout,
            concurrency,
        } => {
            let p: ProbePlan = read(&plan_file)?;
            p.validate()?;
            if dry_run {
                for t in p.targets.iter().filter(|t| t.zone == vantage) {
                    println!(
                        "{}:{} {} {}/{}",
                        t.address,
                        t.port,
                        t.zone.key(),
                        t.service,
                        t.endpoint
                    )
                }
                return Ok(0);
            }
            let output = output
                .ok_or_else(|| Error::Policy("--output is required unless --dry-run".into()))?;
            let rt = tokio::runtime::Runtime::new()?;
            let e = rt.block_on(probe(
                &p,
                vantage,
                source_id,
                Duration::from_millis(timeout),
                concurrency,
            ))?;
            write(&output, &e)?;
            println!(
                "Wrote {} observations to {}",
                e.observations.len(),
                output.display()
            );
            Ok(0)
        }
        Cmd::Audit {
            policy,
            snapshot,
            evidence,
            format,
            output,
            fail_on,
            require_vantage,
            max_age_hours,
        } => {
            let p = Policy::load(&policy)?;
            let s: Snapshot = read(&snapshot)?;
            let ev: Vec<Evidence> = evidence.iter().map(|f| read(f)).collect::<Result<_>>()?;
            let r = audit(&p, &s, &ev, max_age_hours)?;
            let rendered = match format {
                Format::Json => serde_json::to_string_pretty(&r)?,
                Format::Sarif => {
                    serde_json::to_string_pretty(&sarif(&r, &policy.to_string_lossy()))?
                }
                Format::Human => {
                    let mut t=format!("Network Exposure Policy Checker v{}\nDeployment: {}\nSnapshot: {}\n\nSERVICE / ENDPOINT       ZONE       INTENT  OBSERVED\n",r.tool_version,r.deployment,r.snapshot_id);
                    for c in &r.cells {
                        t.push_str(&format!(
                            "{:<24} {:<10} {:<7} {}\n",
                            format!("{}/{}", c.service, c.endpoint),
                            c.zone.key(),
                            format!("{:?}", c.intent).to_lowercase(),
                            c.status
                        ))
                    }
                    t.push_str("\nFINDINGS\n");
                    for f in &r.findings {
                        t.push_str(&format!(
                            "{} {} {}: {}\n",
                            f.severity,
                            f.rule_id,
                            f.service.as_deref().unwrap_or("-"),
                            f.message
                        ))
                    }
                    t
                }
            };
            if let Some(out) = output {
                std::fs::write(out, rendered)?
            } else {
                println!("{rendered}")
            }
            let missing = require_vantage.iter().any(|z| {
                r.coverage
                    .iter()
                    .any(|c| c.zone == *z && c.status != "verified")
            });
            if missing {
                return Ok(5);
            }
            let threshold = fail_on.map(|s| s.rank());
            if threshold.is_some_and(|n| {
                r.findings.iter().any(|f| {
                    let rank = match f.severity.as_str() {
                        "critical" => 4,
                        "high" => 3,
                        "medium" => 2,
                        "low" => 1,
                        _ => 0,
                    };
                    rank >= n
                })
            }) {
                return Ok(1);
            }
            Ok(0)
        }
        Cmd::Explain { rule } => {
            let msg=match rule.as_str(){"PI001"=>"Confirmed forbidden TCP connection. Verify source provenance and restrict the route.","PI002"=>"Broad Docker binding may allow exposure; no external reachability is implied.","PI003"=>"Required endpoint refused all tested connections.","PI004"=>"Endpoint configuration cannot be resolved.","PI005"=>"Published host port differs from declared expectation.","PI006"=>"Required probe coverage is missing or incomplete.","PI007"=>"Networking mode or protocol is unsupported for a clean verdict.",_=>return Err(Error::Policy(format!("unknown rule {rule}")))};
            println!("{rule}: {msg}");
            Ok(0)
        }
        Cmd::Doctor => {
            let status = std::process::Command::new("docker")
                .args(["compose", "version"])
                .status();
            println!(
                "Docker Compose: {}",
                if status.is_ok_and(|s| s.success()) {
                    "available"
                } else {
                    "unavailable"
                }
            );
            Ok(0)
        }
    }
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            let code = match e {
                Error::Policy(_) => 2,
                Error::Docker(_) => 3,
                Error::Evidence(_) => 4,
                Error::Io(_) | Error::Json(_) => 6,
            };
            std::process::exit(code)
        }
    }
}
