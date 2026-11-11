use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
    process::Command,
    time::Duration,
};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("policy: {0}")]
    Policy(String),
    #[error("Docker: {0}")]
    Docker(String),
    #[error("evidence: {0}")]
    Evidence(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}
#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    Local,
    Lan,
    Vpn,
    Internet,
}
impl Zone {
    pub const ALL: [Zone; 4] = [Zone::Local, Zone::Lan, Zone::Vpn, Zone::Internet];
    pub fn key(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Lan => "lan",
            Self::Vpn => "vpn",
            Self::Internet => "internet",
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Normal,
    High,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u8,
    pub project: Project,
    pub targets: BTreeMap<Zone, Targets>,
    pub services: Vec<Service>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub name: String,
    pub compose_files: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub addresses: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub compose_service: String,
    pub sensitivity: Sensitivity,
    pub endpoints: Vec<Endpoint>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub container_port: u16,
    pub host_port: HostPort,
    pub protocol: Protocol,
    pub access: BTreeMap<Zone, Decision>,
    #[serde(default)]
    pub require_reachable_from: Vec<Zone>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostPort {
    Fixed(u16),
    Auto(String),
}
impl HostPort {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Fixed(0) => Err(Error::Policy("host port must be 1..65535".into())),
            Self::Auto(s) if s != "auto" => {
                Err(Error::Policy("host_port must be a number or auto".into()))
            }
            _ => Ok(()),
        }
    }
}
fn valid_host(s: &str) -> bool {
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    if s.contains(':')
        || (s.split('.').count() == 4 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
    {
        return false;
    }
    let s = s.trim_end_matches('.');
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && !s.contains('/')
}
impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let p: Self = serde_yaml_ng::from_str(&raw).map_err(|e| Error::Policy(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Policy(
                "unsupported policy version (expected 1)".into(),
            ));
        }
        if self.project.name.trim().is_empty() || self.project.compose_files.is_empty() {
            return Err(Error::Policy(
                "project name and compose_files are required".into(),
            ));
        }
        let mut names = BTreeSet::new();
        let mut mappings = BTreeSet::new();
        for (zone, target) in &self.targets {
            if target.addresses.is_empty() {
                return Err(Error::Policy(format!("{} has no targets", zone.key())));
            }
            for a in &target.addresses {
                if !valid_host(a) {
                    return Err(Error::Policy(format!("invalid target address: {a}")));
                }
            }
        }
        for s in &self.services {
            if s.name.trim().is_empty()
                || s.compose_service.trim().is_empty()
                || !names.insert(&s.name)
            {
                return Err(Error::Policy(format!(
                    "invalid or duplicate service: {}",
                    s.name
                )));
            }
            let mut endpoints = BTreeSet::new();
            for e in &s.endpoints {
                if e.name.trim().is_empty() || e.container_port == 0 || !endpoints.insert(&e.name) {
                    return Err(Error::Policy(format!(
                        "invalid or duplicate endpoint: {}/{}",
                        s.name, e.name
                    )));
                }
                e.host_port.validate()?;
                if !mappings.insert((&s.compose_service, e.container_port, e.protocol as u8)) {
                    return Err(Error::Policy(format!(
                        "ambiguous Compose endpoint mapping: {}/{}",
                        s.compose_service, e.container_port
                    )));
                }
                for z in Zone::ALL {
                    if !e.access.contains_key(&z) {
                        return Err(Error::Policy(format!(
                            "{}/{} missing {} access",
                            s.name,
                            e.name,
                            z.key()
                        )));
                    }
                }
                for z in &e.require_reachable_from {
                    if e.access.get(z) != Some(&Decision::Allow) {
                        return Err(Error::Policy(format!(
                            "{}/{} requires reachability in a denied zone",
                            s.name, e.name
                        )));
                    }
                }
            }
        }
        Ok(())
    }
    pub fn id(&self) -> String {
        digest(&serde_json::to_vec(self).unwrap_or_default())
    }
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Binding {
    pub service: String,
    pub container_port: u16,
    pub host_port: u16,
    pub protocol: Protocol,
    pub host_ip: String,
    pub source: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u8,
    pub policy_id: String,
    pub deployment: String,
    pub id: String,
    pub captured_at: DateTime<Utc>,
    pub runtime_available: bool,
    pub bindings: Vec<Binding>,
    pub unsupported: Vec<String>,
    pub compose_services: Vec<String>,
    #[serde(default)]
    pub runtime_services: Vec<String>,
}
fn docker(args: &[String]) -> Result<String> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| Error::Docker(e.to_string()))?;
    if !out.status.success() {
        return Err(Error::Docker(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}
fn compose_args(policy: &Policy, base: &Path, tail: &[&str]) -> Vec<String> {
    let mut a = vec!["compose".into()];
    for f in &policy.project.compose_files {
        a.push("-f".into());
        a.push(base.join(f).to_string_lossy().into_owned())
    }
    a.extend(tail.iter().map(|s| s.to_string()));
    a
}
fn port_number(v: &serde_json::Value) -> Option<u16> {
    v.as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| v.as_str()?.parse().ok())
}
fn protocol(v: Option<&serde_json::Value>) -> Option<Protocol> {
    match v.and_then(|x| x.as_str()).unwrap_or("tcp") {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}
pub fn inspect(policy: &Policy, base: &Path, config_only: bool) -> Result<Snapshot> {
    let raw = docker(&compose_args(policy, base, &["config", "--format", "json"]))?;
    let config: serde_json::Value = serde_json::from_str(&raw)?;
    let obj = config
        .get("services")
        .and_then(|v| v.as_object())
        .ok_or_else(|| Error::Docker("Compose config has no services object".into()))?;
    let mut bindings = Vec::new();
    let mut unsupported = Vec::new();
    let mut services = Vec::new();
    for (name, svc) in obj {
        services.push(name.clone());
        if svc.get("network_mode").and_then(|v| v.as_str()) == Some("host") {
            unsupported.push(format!("{name}: host networking"));
            continue;
        }
        if let Some(ports) = svc.get("ports").and_then(|v| v.as_array()) {
            for p in ports {
                let Some(cp) = p.get("target").and_then(port_number) else {
                    unsupported.push(format!("{name}: unresolved target port"));
                    continue;
                };
                let hp = p.get("published").and_then(port_number);
                let Some(pr) = protocol(p.get("protocol")) else {
                    unsupported.push(format!("{name}:{cp}: unsupported port protocol"));
                    continue;
                };
                if let Some(hp) = hp {
                    bindings.push(Binding {
                        service: name.clone(),
                        container_port: cp,
                        host_port: hp,
                        protocol: pr,
                        host_ip: p
                            .get("host_ip")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0.0.0.0")
                            .to_string(),
                        source: "compose".into(),
                    })
                } else {
                    unsupported.push(format!(
                        "{name}:{cp}: dynamic port unresolved without runtime"
                    ))
                }
            }
        }
    }
    let mut runtime_available = false;
    let mut runtime_services = Vec::new();
    if !config_only {
        let ps = docker(&compose_args(
            policy,
            base,
            &["ps", "--all", "--format", "json"],
        ))?;
        let rows: Vec<serde_json::Value> = if ps.trim().starts_with('[') {
            serde_json::from_str(&ps)?
        } else {
            ps.lines()
                .filter(|l| !l.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<std::result::Result<_, _>>()?
        };
        runtime_available = true;
        for row in rows {
            let id = row
                .get("ID")
                .or_else(|| row.get("Id"))
                .and_then(|v| v.as_str());
            let Some(id) = id else { continue };
            let iraw = docker(&["inspect".into(), id.into()])?;
            let iv: serde_json::Value = serde_json::from_str(&iraw)?;
            let Some(c) = iv.as_array().and_then(|a| a.first()) else {
                continue;
            };
            let name = c
                .pointer("/Config/Labels/com.docker.compose.service")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !services.iter().any(|s| s == name) {
                continue;
            }
            runtime_services.push(name.to_string());
            if let Some(map) = c
                .pointer("/NetworkSettings/Ports")
                .and_then(|v| v.as_object())
            {
                for (key, arr) in map {
                    let mut k = key.split('/');
                    let Some(cp) = k.next().and_then(|s| s.parse::<u16>().ok()) else {
                        continue;
                    };
                    let Some(pr) = (match k.next() {
                        Some("tcp") => Some(Protocol::Tcp),
                        Some("udp") => Some(Protocol::Udp),
                        _ => None,
                    }) else {
                        unsupported.push(format!("{name}:{key}: unsupported runtime protocol"));
                        continue;
                    };
                    if let Some(list) = arr.as_array() {
                        for b in list {
                            if let (Some(ip), Some(hp)) = (
                                b.get("HostIp").and_then(|v| v.as_str()),
                                b.get("HostPort").and_then(port_number),
                            ) {
                                bindings.push(Binding {
                                    service: name.into(),
                                    container_port: cp,
                                    host_port: hp,
                                    protocol: pr,
                                    host_ip: ip.into(),
                                    source: "runtime".into(),
                                })
                            }
                        }
                    }
                }
            }
        }
    }
    runtime_services.sort();
    runtime_services.dedup();
    if runtime_available {
        unsupported.retain(|u| !u.contains("dynamic port unresolved without runtime"));
    }
    bindings.sort_by(|a, b| {
        (
            &a.service,
            a.container_port,
            a.host_port,
            &a.host_ip,
            &a.source,
        )
            .cmp(&(
                &b.service,
                b.container_port,
                b.host_port,
                &b.host_ip,
                &b.source,
            ))
    });
    bindings.dedup_by(|a, b| {
        a.service == b.service
            && a.container_port == b.container_port
            && a.host_port == b.host_port
            && a.host_ip == b.host_ip
            && a.protocol == b.protocol
            && a.source == b.source
    });
    let id = digest(&serde_json::to_vec(&(
        &policy.id(),
        &bindings,
        &unsupported,
        &services,
    ))?);
    Ok(Snapshot {
        schema_version: 1,
        policy_id: policy.id(),
        deployment: policy.project.name.clone(),
        id,
        captured_at: Utc::now(),
        runtime_available,
        bindings,
        unsupported,
        compose_services: services,
        runtime_services,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeTarget {
    pub service: String,
    pub endpoint: String,
    pub zone: Zone,
    pub address: String,
    pub port: u16,
    pub protocol: Protocol,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbePlan {
    pub schema_version: u8,
    pub policy_id: String,
    pub snapshot_id: String,
    pub id: String,
    pub deployment: String,
    pub targets: Vec<ProbeTarget>,
}
impl ProbePlan {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.policy_id.len() != 64
            || self.snapshot_id.is_empty()
            || self.id != digest(&serde_json::to_vec(&(&self.snapshot_id, &self.targets))?)
        {
            return Err(Error::Evidence(
                "probe plan identifier or schema is invalid".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for t in &self.targets {
            if !valid_host(&t.address)
                || t.port == 0
                || t.protocol != Protocol::Tcp
                || t.service.is_empty()
                || t.endpoint.is_empty()
                || !seen.insert((&t.service, &t.endpoint, t.zone, &t.address, t.port))
            {
                return Err(Error::Evidence("invalid or duplicate probe target".into()));
            }
        }
        Ok(())
    }
}
pub fn plan(policy: &Policy, s: &Snapshot) -> Result<ProbePlan> {
    if s.policy_id != policy.id() {
        return Err(Error::Evidence("snapshot policy mismatch".into()));
    }
    let mut targets = Vec::new();
    for svc in &policy.services {
        for ep in &svc.endpoints {
            if ep.protocol != Protocol::Tcp {
                continue;
            }
            let mut ports = BTreeSet::new();
            for b in &s.bindings {
                if b.service == svc.compose_service
                    && b.container_port == ep.container_port
                    && b.protocol == ep.protocol
                {
                    ports.insert(b.host_port);
                }
            }
            for z in Zone::ALL {
                if let Some(t) = policy.targets.get(&z) {
                    for a in &t.addresses {
                        for p in &ports {
                            targets.push(ProbeTarget {
                                service: svc.name.clone(),
                                endpoint: ep.name.clone(),
                                zone: z,
                                address: a.clone(),
                                port: *p,
                                protocol: ep.protocol,
                            })
                        }
                    }
                }
            }
        }
    }
    let id = digest(&serde_json::to_vec(&(&s.id, &targets))?);
    Ok(ProbePlan {
        schema_version: 1,
        policy_id: policy.id(),
        snapshot_id: s.id.clone(),
        id,
        deployment: s.deployment.clone(),
        targets,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Connected,
    ConnectionRefused,
    TimedOut,
    NetworkUnreachable,
    DnsResolutionFailed,
    ProbeError,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub target: ProbeTarget,
    pub resolved_ip: Option<IpAddr>,
    pub outcome: Outcome,
    pub elapsed_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub schema_version: u8,
    pub tool_version: String,
    pub plan_id: String,
    pub policy_id: String,
    pub snapshot_id: String,
    pub source_zone: Zone,
    pub source_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub observations: Vec<Observation>,
}
pub async fn probe(
    p: &ProbePlan,
    zone: Zone,
    source_id: String,
    timeout: Duration,
    concurrency: usize,
) -> Result<Evidence> {
    p.validate()?;
    if concurrency == 0 || concurrency > 32 || timeout.as_millis() == 0 || timeout.as_secs() > 30 {
        return Err(Error::Evidence("invalid probe plan or limits".into()));
    }
    let start = Utc::now();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut set = tokio::task::JoinSet::new();
    for t in p.targets.iter().filter(|t| t.zone == zone) {
        if !valid_host(&t.address) || t.port == 0 || t.protocol != Protocol::Tcp {
            return Err(Error::Evidence("invalid plan target".into()));
        }
        let t = t.clone();
        let sem = semaphore.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await;
            let resolved: Vec<_> = match tokio::net::lookup_host((t.address.as_str(), t.port)).await
            {
                Ok(a) => a.collect(),
                Err(_) => {
                    return vec![Observation {
                        target: t.clone(),
                        resolved_ip: None,
                        outcome: Outcome::DnsResolutionFailed,
                        elapsed_ms: 0,
                    }]
                }
            };
            if resolved.is_empty() {
                return vec![Observation {
                    target: t,
                    resolved_ip: None,
                    outcome: Outcome::DnsResolutionFailed,
                    elapsed_ms: 0,
                }];
            }
            let mut out = Vec::new();
            for addr in resolved {
                let now = std::time::Instant::now();
                let outcome =
                    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await
                    {
                        Ok(Ok(_)) => Outcome::Connected,
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                            Outcome::ConnectionRefused
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NetworkUnreachable => {
                            Outcome::NetworkUnreachable
                        }
                        Ok(Err(_)) => Outcome::ProbeError,
                        Err(_) => Outcome::TimedOut,
                    };
                out.push(Observation {
                    target: t.clone(),
                    resolved_ip: Some(addr.ip()),
                    outcome,
                    elapsed_ms: now.elapsed().as_millis() as u64,
                })
            }
            out
        });
    }
    let mut observations = Vec::new();
    while let Some(r) = set.join_next().await {
        observations.extend(r.map_err(|e| Error::Evidence(e.to_string()))?)
    }
    observations.sort_by(|a, b| {
        (
            &a.target.service,
            &a.target.endpoint,
            a.target.zone,
            &a.target.address,
            a.target.port,
            a.resolved_ip,
        )
            .cmp(&(
                &b.target.service,
                &b.target.endpoint,
                b.target.zone,
                &b.target.address,
                b.target.port,
                b.resolved_ip,
            ))
    });
    Ok(Evidence {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        plan_id: p.id.clone(),
        policy_id: p.policy_id.clone(),
        snapshot_id: p.snapshot_id.clone(),
        source_zone: zone,
        source_id,
        started_at: start,
        completed_at: Utc::now(),
        observations,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    pub service: Option<String>,
    pub endpoint: Option<String>,
    pub zone: Option<Zone>,
    pub message: String,
    pub remediation: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cell {
    pub service: String,
    pub endpoint: String,
    pub zone: Zone,
    pub intent: Decision,
    pub status: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u8,
    pub tool_version: String,
    pub deployment: String,
    pub policy_id: String,
    pub snapshot_id: String,
    pub findings: Vec<Finding>,
    pub cells: Vec<Cell>,
    pub coverage: Vec<Coverage>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coverage {
    pub zone: Zone,
    pub planned_targets: usize,
    pub observed_targets: usize,
    pub status: String,
}
pub fn audit(
    policy: &Policy,
    s: &Snapshot,
    evidence: &[Evidence],
    max_age_hours: i64,
) -> Result<Report> {
    let p = plan(policy, s)?;
    p.validate()?;
    let now = Utc::now();
    let allowed: BTreeSet<_> = p
        .targets
        .iter()
        .map(|t| (&t.service, &t.endpoint, t.zone, &t.address, t.port))
        .collect();
    for ev in evidence {
        if ev.schema_version != 1
            || ev.plan_id != p.id
            || ev.policy_id != p.policy_id
            || ev.snapshot_id != s.id
            || ev.started_at > ev.completed_at
            || ev.completed_at > now + chrono::Duration::minutes(5)
            || now - ev.completed_at > chrono::Duration::hours(max_age_hours)
        {
            return Err(Error::Evidence("incompatible or stale evidence".into()));
        }
        for o in &ev.observations {
            if o.target.zone != ev.source_zone
                || o.target.protocol != Protocol::Tcp
                || (o.outcome == Outcome::Connected && o.resolved_ip.is_none())
                || !allowed.contains(&(
                    &o.target.service,
                    &o.target.endpoint,
                    o.target.zone,
                    &o.target.address,
                    o.target.port,
                ))
            {
                return Err(Error::Evidence(
                    "observation outside plan or source zone".into(),
                ));
            }
        }
    }
    let mut findings = Vec::new();
    let mut cells = Vec::new();
    for svc in &policy.services {
        if !s.compose_services.contains(&svc.compose_service) {
            findings.push(Finding {
                rule_id: "PI004".into(),
                severity: "medium".into(),
                confidence: "confirmed".into(),
                service: Some(svc.name.clone()),
                endpoint: None,
                zone: None,
                message: "referenced Compose service is missing".into(),
                remediation: "Correct compose_service or Compose files".into(),
            });
        } else if s.runtime_available && !s.runtime_services.contains(&svc.compose_service) {
            findings.push(Finding {
                rule_id: "PI004".into(),
                severity: "info".into(),
                confidence: "inconclusive".into(),
                service: Some(svc.name.clone()),
                endpoint: None,
                zone: None,
                message: "Compose service has no inspected runtime container".into(),
                remediation: "Check container state and deployment selection".into(),
            });
        }
    }
    for b in s.bindings.iter().filter(|b| b.source == "runtime") {
        let declared = policy.services.iter().any(|svc| {
            svc.compose_service == b.service
                && svc
                    .endpoints
                    .iter()
                    .any(|e| e.container_port == b.container_port && e.protocol == b.protocol)
        });
        if !declared {
            findings.push(Finding {
                rule_id: "PI005".into(),
                severity: "medium".into(),
                confidence: "confirmed".into(),
                service: Some(b.service.clone()),
                endpoint: None,
                zone: None,
                message: format!(
                    "unexpected runtime published port {}/{} on {}",
                    b.host_port,
                    if b.protocol == Protocol::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    },
                    b.host_ip
                ),
                remediation: "Review the runtime mapping and declare or remove the endpoint".into(),
            });
        }
    }
    let mut coverage = Vec::new();
    for z in Zone::ALL {
        let planned: Vec<_> = p.targets.iter().filter(|t| t.zone == z).collect();
        let observed = planned
            .iter()
            .filter(|t| {
                evidence.iter().flat_map(|e| &e.observations).any(|o| {
                    o.target.zone == z
                        && o.target.service == t.service
                        && o.target.endpoint == t.endpoint
                        && o.target.address == t.address
                        && o.target.port == t.port
                        && o.resolved_ip.is_some()
                })
            })
            .count();
        let status = if planned.is_empty() {
            "unsupported"
        } else if observed == planned.len() {
            "verified"
        } else if observed == 0 {
            "not_verified"
        } else {
            "partially_verified"
        };
        if status != "verified" {
            findings.push(Finding {
                rule_id: "PI006".into(),
                severity: "info".into(),
                confidence: "inconclusive".into(),
                service: None,
                endpoint: None,
                zone: Some(z),
                message: format!(
                    "{}: {observed}/{} planned targets observed",
                    z.key(),
                    planned.len()
                ),
                remediation: "Run the exact plan from an authorized source in this zone".into(),
            });
        }
        coverage.push(Coverage {
            zone: z,
            planned_targets: planned.len(),
            observed_targets: observed,
            status: status.into(),
        });
    }
    for svc in &policy.services {
        for ep in &svc.endpoints {
            let relevant: Vec<_> = s
                .bindings
                .iter()
                .filter(|b| {
                    b.service == svc.compose_service
                        && b.container_port == ep.container_port
                        && b.protocol == ep.protocol
                })
                .collect();
            if ep.protocol == Protocol::Udp {
                findings.push(Finding {
                    rule_id: "PI007".into(),
                    severity: "info".into(),
                    confidence: "inconclusive".into(),
                    service: Some(svc.name.clone()),
                    endpoint: Some(ep.name.clone()),
                    zone: None,
                    message: "UDP verification unsupported".into(),
                    remediation:
                        "Use protocol-specific validation outside Network Exposure Policy Checker"
                            .into(),
                });
            }
            if relevant
                .iter()
                .any(|b| b.host_ip == "0.0.0.0" || b.host_ip == "::")
                && [Zone::Lan, Zone::Vpn, Zone::Internet]
                    .iter()
                    .any(|z| ep.access.get(z) == Some(&Decision::Deny))
            {
                findings.push(Finding{rule_id:"PI002".into(),severity:"medium".into(),confidence:"inferred".into(),service:Some(svc.name.clone()),endpoint:Some(ep.name.clone()),zone:None,message:"Broad Docker host binding may expose a denied endpoint; reachability is unverified".into(),remediation:"Restrict host binding or enforce the intended boundary with network controls".into()});
            }
            if let HostPort::Fixed(expected) = ep.host_port {
                for b in &relevant {
                    if b.host_port != expected {
                        findings.push(Finding {
                            rule_id: "PI005".into(),
                            severity: "medium".into(),
                            confidence: "confirmed".into(),
                            service: Some(svc.name.clone()),
                            endpoint: Some(ep.name.clone()),
                            zone: None,
                            message: format!(
                                "host port {} differs from declared {expected}",
                                b.host_port
                            ),
                            remediation: "Align the policy or Docker published port".into(),
                        })
                    }
                }
            }
            for z in Zone::ALL {
                let intent = ep.access[&z];
                let obs: Vec<_> = evidence
                    .iter()
                    .flat_map(|e| e.observations.iter())
                    .filter(|o| {
                        o.target.service == svc.name
                            && o.target.endpoint == ep.name
                            && o.target.zone == z
                    })
                    .collect();
                let connected = obs.iter().any(|o| o.outcome == Outcome::Connected);
                let zone_targets: Vec<_> = p
                    .targets
                    .iter()
                    .filter(|t| t.zone == z && t.service == svc.name && t.endpoint == ep.name)
                    .collect();
                let complete = !zone_targets.is_empty()
                    && zone_targets.iter().all(|t| {
                        obs.iter().any(|o| {
                            o.target.address == t.address
                                && o.target.port == t.port
                                && o.resolved_ip.is_some()
                        })
                    });
                let status = if ep.protocol == Protocol::Udp {
                    "unsupported"
                } else if connected && intent == Decision::Deny {
                    "violation"
                } else if connected {
                    "connected"
                } else if obs.is_empty() {
                    "not_tested"
                } else if !complete {
                    "partially_verified"
                } else if obs.iter().all(|o| o.outcome == Outcome::ConnectionRefused) {
                    "refused_on_tested_targets"
                } else {
                    "inconclusive"
                };
                if status == "violation" {
                    findings.push(Finding{rule_id:"PI001".into(),severity:if svc.sensitivity==Sensitivity::High&&z==Zone::Internet{"critical"}else{"high"}.into(),confidence:"confirmed".into(),service:Some(svc.name.clone()),endpoint:Some(ep.name.clone()),zone:Some(z),message:format!("forbidden TCP connection succeeded from declared {} source",z.key()),remediation:"Restrict reachability at the binding, firewall, routing, or proxy layer".into()})
                }
                if ep.require_reachable_from.contains(&z) && status == "refused_on_tested_targets" {
                    findings.push(Finding {
                        rule_id: "PI003".into(),
                        severity: "medium".into(),
                        confidence: "confirmed".into(),
                        service: Some(svc.name.clone()),
                        endpoint: Some(ep.name.clone()),
                        zone: Some(z),
                        message: "required endpoint refused all tested connections".into(),
                        remediation: "Check service state, binding, and route".into(),
                    })
                }
                cells.push(Cell {
                    service: svc.name.clone(),
                    endpoint: ep.name.clone(),
                    zone: z,
                    intent,
                    status: status.into(),
                })
            }
        }
    }
    for u in &s.unsupported {
        findings.push(Finding {
            rule_id: "PI007".into(),
            severity: "info".into(),
            confidence: "inconclusive".into(),
            service: None,
            endpoint: None,
            zone: None,
            message: u.clone(),
            remediation: "Inspect this configuration separately".into(),
        })
    }
    findings.sort_by(|a, b| {
        (&a.rule_id, &a.service, &a.endpoint, &a.zone, &a.message).cmp(&(
            &b.rule_id,
            &b.service,
            &b.endpoint,
            &b.zone,
            &b.message,
        ))
    });
    Ok(Report {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        deployment: s.deployment.clone(),
        policy_id: p.policy_id,
        snapshot_id: s.id.clone(),
        findings,
        cells,
        coverage,
    })
}
pub fn sarif(r: &Report, policy_path: &str) -> serde_json::Value {
    let rules = [
        ("PI001", "Confirmed unintended reachability"),
        ("PI002", "Potentially overbroad binding"),
        ("PI003", "Required endpoint unavailable"),
        ("PI004", "Unresolved configuration"),
        ("PI005", "Unexpected port mapping"),
        ("PI006", "Incomplete coverage"),
        ("PI007", "Unsupported networking"),
    ];
    serde_json::json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"Network Exposure Policy Checker","version":r.tool_version,"rules":rules.iter().map(|(id,name)|serde_json::json!({"id":id,"name":name,"shortDescription":{"text":name}})).collect::<Vec<_>>() }},"results":r.findings.iter().map(|f|serde_json::json!({"ruleId":f.rule_id,"level":match f.severity.as_str(){"critical"|"high"=>"error","medium"=>"warning",_=>"note"},"message":{"text":f.message},"locations":[{"physicalLocation":{"artifactLocation":{"uri":policy_path}}}],"partialFingerprints":{"network-exposure-policy-checker/v1":digest(format!("{}|{:?}|{:?}|{:?}",f.rule_id,f.service,f.endpoint,f.zone).as_bytes())},"properties":{"confidence":f.confidence,"zone":f.zone}})).collect::<Vec<_>>() }]})
}
