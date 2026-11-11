# Architecture

The CLI loads and validates a versioned policy, invokes Docker Compose for normalized configuration and Docker inspect for runtime port bindings, creates an exact probe plan, and writes portable evidence. The audit function accepts only the policy, snapshot, and evidence structures; it does not execute Docker or open sockets. Reports preserve separate intent, binding, observation, and coverage data. JSON output is versioned with `schema_version: 1`; SARIF uses rule IDs PI001–PI007.
