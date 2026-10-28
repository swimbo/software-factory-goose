# Trusted inference launcher fixture

The disposable Restate replay harness now invokes a **fixture-only Python launcher** against the unregistered `InferenceAuthority` and a separate synthetic loopback HTTP provider. The fixture launcher hashes the exact fixed request bytes, uses a fixed synthetic model, review digest and attempt, prepares the reservation, obtains a successful `begin`, and makes one provider request. It never retries a failed or uncertain provider request. No production code or service was enabled.

The full disposable Restate/PostgreSQL replay fixture passed with these controls:

- Ten simultaneous attempts with the same ID resulted in one successful launch and exactly one provider request. Reusing that ID for changed request bytes was refused.
- A discarded prepare acknowledgement was reconciled by exact retry and resulted in one provider call. A discarded begin acknowledgement resulted in no provider call and could not be retried.
- A provider accepted a request then closed without a response; retry was refused and the provider saw one call. A child launcher exiting after begin and before send caused no call and retry was refused. A separate child was killed after the synthetic provider accepted its request; retry was refused and the provider saw one call.
- All six resulting records remained `DispatchingUnknown` and refused begin after graceful and SIGKILL Restate restarts. Restate itself was killed only after acknowledged journal operations; no in-flight journal mutation was killed.

The fixture uses random loopback ports, synthetic content, processes and databases created for the test. The provider counter observes requests; it does not represent billing or a real Bifrost provider. Restart checks read the journal and do not restart the synthetic provider.

This experiment assumes a trusted launcher that follows the protocol. The Python module can be called with arbitrary fixture inputs and the loopback provider has no authentication; a malicious or compromised launcher could send directly or reuse a successful begin response. It is not a protected capability, runtime proxy, credential broker, sandbox or no-bypass proof. The digest and attempt are supplied by the fixture, not derived from an authenticated live lease; live price and daily limits, existing-ledger migration, trusted launcher identity, request/result reconciliation, streaming, and worker containment remain unresolved. No live model or external credentials were used.
