# Network Exposure Policy Checker

Declare intended network reachability. Detect unintended exposure.

Network Exposure Policy Checker is a Rust CLI for comparing a Docker Compose deployment's declared access policy with port publishing and operator-collected TCP connection evidence. It keeps configuration warnings distinct from confirmed reachability violations.

## Why

An open or broadly bound port does not tell you whether it violates a deployment boundary. A Docker binding to `0.0.0.0` suggests possible exposure but does not prove that a LAN or Internet client can connect. Network Exposure Policy Checker records both facts separately.

| Service    | Local | LAN   | VPN   | Internet |
| ---------- | ----- | ----- | ----- | -------- |
| PostgreSQL | allow | deny  | deny  | deny     |
| Redis      | allow | deny  | deny  | deny     |
| API        | allow | allow | allow | allow    |
| Admin      | allow | deny  | allow | deny     |

## Install

```sh
cargo install --path .
```

Install from a source checkout with stable Rust. Docker Compose is needed only for `init` and `inspect`.

## Quick start

See [the safe example](examples/basic-stack/README.md). From its directory:

```sh
network-exposure-policy-checker policy validate --file network-exposure-policy-checker.yaml
network-exposure-policy-checker inspect --policy network-exposure-policy-checker.yaml --config-only --output snapshot.json
network-exposure-policy-checker plan --policy network-exposure-policy-checker.yaml --snapshot snapshot.json --output plan.json
network-exposure-policy-checker probe --plan plan.json --vantage local --dry-run
network-exposure-policy-checker audit --policy network-exposure-policy-checker.yaml --snapshot snapshot.json --format json
```

Omit `--config-only` to request runtime Docker inspection. `init --compose compose.yaml --output network-exposure-policy-checker.yaml` produces a draft with `REVIEW` decisions; review and replace every decision before validation.

Run an authorized probe on each independent source machine:

```sh
network-exposure-policy-checker probe --plan plan.json --vantage lan --source-id lan-host-01 --output lan-evidence.json
```

Then pass one or more `--evidence` files to `audit`. Use `--format json` or `--format sarif` with `--output`. `--fail-on high` exits 1 for findings at or above the threshold. `--require-vantage local,lan` exits 5 unless every planned target in those zones has a connection attempt recorded.

## Policy

The [example policy](examples/basic-stack/network-exposure-policy-checker.yaml) shows the complete version 1 format. Each endpoint declares all four access decisions. `allow` is permission, not an uptime requirement; `require_reachable_from` adds an availability requirement. `host_port: auto` represents a Docker-assigned host port. UDP can be declared but is not verified.

## Findings and coverage

- `PI001`: a forbidden TCP connection succeeded from the declared zone.
- `PI002`: a broad Docker host binding may expose a denied endpoint; actual reachability is unknown until probed.
- `PI003`: a required endpoint refused tested connections.
- `PI005`: a published host port differs from policy.
- `PI007`: unsupported networking or protocol.

Coverage counts every exact planned target as `verified`, `partially_verified`, or `not_verified`; `--require-vantage` fails unless all targets in that zone were observed. A missing probe remains `not_tested`. A timeout is `inconclusive`, and a refusal applies only to the tested address and source. `explain PI001` through `explain PI007` provide short rule descriptions.

Exit codes: `0` successful, `1` finding threshold, `2` invalid policy/config, `3` Docker failure, `4` invalid evidence, `5` required vantage missing, `6` I/O or internal error.

## Limits

Source zones are declared by operators and are not authenticated. Evidence JSON and probe plans are not signed. Plan IDs detect accidental changes but an adversary who can rewrite a plan can recompute its ID; distribute plans through a trusted channel. Probes establish only TCP connection success at a particular address and time; they do not assess application authentication. Static analysis does not prove external reachability. Host networking and unusual Docker routing need independent verification. See [threat model](docs/threat-model.md), [probe model](docs/probe-model.md), and [Docker behavior](docs/docker-behavior.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

See [CI integration](docs/ci-integration.md), [architecture](docs/architecture.md), [limitations](docs/limitations.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [LICENSE](LICENSE).

## License

Network Exposure Policy Checker is licensed under the MIT License. See [LICENSE](LICENSE).
