# Contributing to Network Exposure Policy Checker

Network Exposure Policy Checker reports security boundaries, so changes to evidence handling and finding language need careful review. Open an issue to discuss a substantial change before building it. Small bug fixes and documentation corrections can go straight to a pull request.

## Development

Use stable Rust. Docker Compose is needed for live inspection, but the routine test suite uses local fixtures and a loopback listener.

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

Add a regression test for behavior changes. In particular, distinguish Docker configuration from observed reachability, and preserve unknown or incomplete coverage when evidence is absent. Do not add probes outside an explicit plan or include secrets from Compose output in reports.

## Pull requests

Describe the behavior change, the validation you ran, and any Docker or operating system behavior you could not exercise. Keep examples safe by binding demo services to loopback. Please do not include real credentials, network inventories, or evidence files from private deployments.

Report suspected security vulnerabilities privately using [GitHub security advisories](https://github.com/ranajahanzaib/network-exposure-policy-checker/security/advisories/new), following [SECURITY.md](SECURITY.md).
