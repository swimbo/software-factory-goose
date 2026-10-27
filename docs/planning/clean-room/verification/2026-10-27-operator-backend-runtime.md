# Real Unix approval backend and lost acknowledgement

Date: 2026-10-27. Disposable local Restate/PostgreSQL fixture only. No production operator route, OS principal, Git action or standing socket was enabled.

`operator_backend_fixture` exercises the actual `UnixApprovalBackend` against the synthetic `ApprovalJournal` registered by the existing disposable SDK fixture. The Python proxy helper creates two mode0600 Unix sockets inside a fresh mode0700 workspace directory, with fixed forwarding to the explicitly provided disposable loopback Restate ingress. Existing protected-path, ACL, socket identity and peer-preflight checks run without bypass. The journal's configured operator1001 and audience`fixture` are synthetic; the example intentionally tests the backend contract directly, not the outer operator router's separate-account authentication.

Verified against real journal state:

- Absent-body status before issuance returns no record.
- Issue returns the exact synthetic action, nonce, configured principal and300000ms lifetime; status returns the same record.
- Exact reissue preserves the original record and lifetime. Changing the action under the same nonce is refused.
- Consuming an altered candidate revision fails; subsequent status equals the original unconsumed record.
- Exact consumption records a timestamp. Replay fails, status preserves the consumed record, and exact reissue cannot reopen it.
- A second nonce is issued normally. A separate private fault socket forwards its consume request, waits for actual upstream response bytes, then closes without forwarding those bytes. The typed backend reports an error. A subsequent call through the normal socket confirms the same action/nonce was durably marked consumed. Replay remains refused and another status read preserves that decision.

The relay asserts that response loss actually occurred. Empty kernel-peer preflight connections cannot trigger injection: it requires request bytes to have been forwarded first. Only the dedicated synthetic consume uses the fault socket. No payloads, tokens or response bodies are logged. Both proxy listeners shut down and their threads join before temporary directory cleanup; the existing parent fixture also cleans up its SDK, Restate and PostgreSQL processes. Relay connections retain fixed upstream selection, an eight-active-connection cap,20-second lifetime and1MiB traffic cap.

Validation: built all three examples with `cargo build -p control-plane --features restate --example operator_backend_fixture --example worker_backend_fixture --example restate_replay_fixture`, then ran `python3 tests/fixtures/restate_replay.py`. It exited0 with all three PASS lines: worker Unix backend contracts; approval Unix backend contracts and lost reply; original graceful/SIGKILL replay checks. The newly consumed approval records were created after the existing restart assertions, so their specific nonces were not additionally tested across a server restart. The lost-reply check proves persisted journal state is observable after a missing acknowledgement; it does not prove an external action executed.

Limits: same-host/same-account proxy access and synthetic journal principal do not establish production private ingress, generator denial of the loopback/admin ports, separate OS identities, human presence or MFA. The outer operator router and authoritative eligibility guard are covered separately by local fixtures, not connected here to a deployed authoritative state source. No Git executor is called or available through this backend. Durable atomic revalidation/consumption/execution and recovery remain integration gates.

The new example passed strict Clippy (`cargo clippy -p control-plane --features restate --example operator_backend_fixture -- -D warnings`), Python syntax parsing and `git diff --check`.
