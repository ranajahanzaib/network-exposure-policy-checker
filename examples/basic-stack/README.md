# Safe local example

All published ports bind to IPv4 loopback. The PostgreSQL password in `compose.yaml` is a public demo value for this disposable local example; do not reuse it. The policy uses documentation-only remote addresses; replace them with real, authorized targets before remote probing.

```sh
cd examples/basic-stack
docker compose up -d
network-exposure-policy-checker policy validate --file portintent.yaml
network-exposure-policy-checker inspect --policy portintent.yaml --output snapshot.json
network-exposure-policy-checker plan --policy portintent.yaml --snapshot snapshot.json --output plan.json
network-exposure-policy-checker probe --plan plan.json --vantage local --dry-run
network-exposure-policy-checker probe --plan plan.json --vantage local --output local-evidence.json
network-exposure-policy-checker audit --policy portintent.yaml --snapshot snapshot.json --evidence local-evidence.json
network-exposure-policy-checker audit --policy portintent.yaml --snapshot snapshot.json --evidence local-evidence.json --format sarif --output audit.sarif
```

Run remote probes only from genuinely independent, authorized machines. `--config-only` allows inspection without a running daemon. Never label replayed fixture observations as live evidence.
