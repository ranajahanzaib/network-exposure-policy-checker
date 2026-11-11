# CI integration

See [the example consumer workflow](../examples/ci/README.md). Configuration-only CI checks Compose publishing without asserting live reachability. Runtime CI needs Docker access to the actual deployment. Remote zones need separate probe machines, transferred plans, and imported evidence. `--fail-on` sets a severity threshold; `--require-vantage` fails with exit 5 unless every planned target in each specified zone has an observation. Preserve audit JSON and SARIF artifacts even when the threshold fails.
