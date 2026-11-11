# Consumer CI workflow

Use the workflow below in a repository containing `compose.yaml` and `network-exposure-policy-checker.yaml`. Pull requests can validate and inspect the normalized Compose configuration without a deployment. A self-hosted runner with Docker access is required for runtime inspection. LAN, VPN, and Internet verification must run from independent, authorized positions; a GitHub-hosted runner is not automatically in those zones.

```yaml
name: Network intent
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  config:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: ranajahanzaib/network-exposure-policy-checker
          path: network-exposure-policy-checker-tool
          ref: main
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --path network-exposure-policy-checker-tool --locked
      - run: network-exposure-policy-checker policy validate --file network-exposure-policy-checker.yaml
      - run: network-exposure-policy-checker inspect --policy network-exposure-policy-checker.yaml --config-only --output snapshot.json
      - run: network-exposure-policy-checker plan --policy network-exposure-policy-checker.yaml --snapshot snapshot.json --output plan.json
      - run: network-exposure-policy-checker audit --policy network-exposure-policy-checker.yaml --snapshot snapshot.json --format sarif --output audit.sarif --fail-on high
        id: audit
        continue-on-error: true
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: network-exposure-policy-checker-audit
          path: |
            snapshot.json
            plan.json
            audit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: audit.sarif
      - run: test '${{ steps.audit.outcome }}' = success
```

Pin the Network Exposure Policy Checker checkout to a reviewed commit or release tag before adopting this workflow. The `main` reference shows the setup while the first release is pending. SARIF upload requires GitHub Code Scanning support and `security-events: write`; remove that step where unavailable.
