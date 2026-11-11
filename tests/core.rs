use network_exposure_policy_checker::*;
use std::{collections::BTreeMap, net::TcpListener, time::Duration};
fn policy() -> Policy {
    let mut access = BTreeMap::new();
    for z in Zone::ALL {
        access.insert(
            z,
            if z == Zone::Local {
                Decision::Allow
            } else {
                Decision::Deny
            },
        );
    }
    let mut targets = BTreeMap::new();
    for z in Zone::ALL {
        targets.insert(
            z,
            Targets {
                addresses: vec!["127.0.0.1".into()],
            },
        );
    }
    Policy {
        version: 1,
        project: Project {
            name: "test".into(),
            compose_files: vec!["compose.yaml".into()],
        },
        targets,
        services: vec![Service {
            name: "redis".into(),
            compose_service: "redis".into(),
            sensitivity: Sensitivity::High,
            endpoints: vec![Endpoint {
                name: "cache".into(),
                container_port: 6379,
                host_port: HostPort::Fixed(6379),
                protocol: Protocol::Tcp,
                access,
                require_reachable_from: vec![],
            }],
        }],
    }
}
fn snapshot(p: &Policy) -> Snapshot {
    Snapshot {
        schema_version: 1,
        policy_id: p.id(),
        deployment: "test".into(),
        id: "s".into(),
        captured_at: chrono::Utc::now(),
        runtime_available: true,
        bindings: vec![Binding {
            service: "redis".into(),
            container_port: 6379,
            host_port: 6379,
            protocol: Protocol::Tcp,
            host_ip: "0.0.0.0".into(),
            source: "runtime".into(),
        }],
        unsupported: vec![],
        compose_services: vec!["redis".into()],
        runtime_services: vec!["redis".into()],
    }
}
#[test]
fn missing_access_fails() {
    let mut p = policy();
    p.services[0].endpoints[0].access.remove(&Zone::Vpn);
    assert!(p.validate().is_err());
}
#[test]
fn broad_binding_is_only_inferred() {
    let p = policy();
    let r = audit(&p, &snapshot(&p), &[], 24).unwrap();
    assert!(r.findings.iter().any(|f| f.rule_id == "PI002"));
    assert!(!r.findings.iter().any(|f| f.rule_id == "PI001"));
    assert_eq!(
        r.cells
            .iter()
            .find(|c| c.zone == Zone::Internet)
            .unwrap()
            .status,
        "not_tested"
    );
}
#[tokio::test]
async fn forbidden_connection_is_confirmed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let p = policy();
    let mut s = snapshot(&p);
    s.bindings[0].host_port = port;
    let pl = plan(&p, &s).unwrap();
    let ev = probe(
        &pl,
        Zone::Lan,
        "operator-declared-lan".into(),
        Duration::from_millis(500),
        2,
    )
    .await
    .unwrap();
    assert!(ev
        .observations
        .iter()
        .any(|o| o.outcome == Outcome::Connected));
    let r = audit(&p, &s, &[ev], 24).unwrap();
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule_id == "PI001" && f.confidence == "confirmed"));
}
#[test]
fn sarif_has_required_shape() {
    let p = policy();
    let r = audit(&p, &snapshot(&p), &[], 24).unwrap();
    let v = sarif(&r, "network-exposure-policy-checker.yaml");
    assert_eq!(v["version"], "2.1.0");
    assert!(v["runs"][0]["tool"]["driver"]["rules"].is_array());
}
#[test]
fn tampered_plan_is_rejected() {
    let p = policy();
    let mut pl = plan(&p, &snapshot(&p)).unwrap();
    pl.targets[0].address = "other.example".into();
    assert!(pl.validate().is_err());
}
#[test]
fn partial_targets_remain_incomplete() {
    let mut p = policy();
    p.targets
        .get_mut(&Zone::Lan)
        .unwrap()
        .addresses
        .push("127.0.0.2".into());
    let s = snapshot(&p);
    let pl = plan(&p, &s).unwrap();
    let now = chrono::Utc::now();
    let ev = Evidence {
        schema_version: 1,
        tool_version: "0.1.0".into(),
        plan_id: pl.id,
        policy_id: p.id(),
        snapshot_id: s.id.clone(),
        source_zone: Zone::Lan,
        source_id: "test".into(),
        started_at: now,
        completed_at: now,
        observations: vec![Observation {
            target: pl
                .targets
                .iter()
                .find(|t| t.zone == Zone::Lan)
                .unwrap()
                .clone(),
            resolved_ip: Some("127.0.0.1".parse().unwrap()),
            outcome: Outcome::ConnectionRefused,
            elapsed_ms: 1,
        }],
    };
    let r = audit(&p, &s, &[ev], 24).unwrap();
    assert_eq!(
        r.coverage
            .iter()
            .find(|c| c.zone == Zone::Lan)
            .unwrap()
            .status,
        "partially_verified"
    );
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule_id == "PI006" && f.zone == Some(Zone::Lan)));
}
#[test]
fn missing_service_and_unexpected_port_are_reported() {
    let p = policy();
    let mut s = snapshot(&p);
    s.compose_services.clear();
    s.bindings[0].container_port = 9999;
    let r = audit(&p, &s, &[], 24).unwrap();
    assert!(r.findings.iter().any(|f| f.rule_id == "PI004"));
    assert!(r.findings.iter().any(|f| f.rule_id == "PI005"));
}
#[test]
fn partial_refusals_do_not_claim_required_outage() {
    let mut p = policy();
    p.services[0].endpoints[0]
        .require_reachable_from
        .push(Zone::Local);
    p.targets
        .get_mut(&Zone::Local)
        .unwrap()
        .addresses
        .push("127.0.0.2".into());
    let s = snapshot(&p);
    let pl = plan(&p, &s).unwrap();
    let now = chrono::Utc::now();
    let target = pl
        .targets
        .iter()
        .find(|t| t.zone == Zone::Local)
        .unwrap()
        .clone();
    let ev = Evidence {
        schema_version: 1,
        tool_version: "0.1.0".into(),
        plan_id: pl.id,
        policy_id: p.id(),
        snapshot_id: s.id.clone(),
        source_zone: Zone::Local,
        source_id: "test".into(),
        started_at: now,
        completed_at: now,
        observations: vec![Observation {
            target,
            resolved_ip: Some("127.0.0.1".parse().unwrap()),
            outcome: Outcome::ConnectionRefused,
            elapsed_ms: 1,
        }],
    };
    let r = audit(&p, &s, &[ev], 24).unwrap();
    assert!(!r.findings.iter().any(|f| f.rule_id == "PI003"));
    assert_eq!(
        r.cells
            .iter()
            .find(|c| c.zone == Zone::Local)
            .unwrap()
            .status,
        "partially_verified"
    );
}
#[test]
fn malformed_connected_observation_is_rejected() {
    let p = policy();
    let s = snapshot(&p);
    let pl = plan(&p, &s).unwrap();
    let now = chrono::Utc::now();
    let target = pl
        .targets
        .iter()
        .find(|t| t.zone == Zone::Lan)
        .unwrap()
        .clone();
    let ev = Evidence {
        schema_version: 1,
        tool_version: "0.1.0".into(),
        plan_id: pl.id,
        policy_id: p.id(),
        snapshot_id: s.id.clone(),
        source_zone: Zone::Lan,
        source_id: "test".into(),
        started_at: now,
        completed_at: now,
        observations: vec![Observation {
            target,
            resolved_ip: None,
            outcome: Outcome::Connected,
            elapsed_ms: 1,
        }],
    };
    assert!(audit(&p, &s, &[ev], 24).is_err());
}
