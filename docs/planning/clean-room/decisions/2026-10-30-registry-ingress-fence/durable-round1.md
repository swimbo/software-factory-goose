# Durable-runtime response: round 1

## 1. Positive forwarding control and retirement

Agree, with one clarification: the Unix-and-retirement candidate does not need a hypothetical nftables rule to establish the 8080 forwarding risk. My position's instruction to block direct ports for that first control was unnecessarily prescriptive. Run a same-UID positive request through Restate 8080 to the old SDK and observe the synthetic durable counter change; then retire and restart-fence the exact old endpoint, retain its deployment record, and demonstrate that direct and forwarded requests, including an existing connection, cannot cause another old effect. Probe all ungated endpoints in the live inventory rather than extrapolating from SDK4. Record listener/process/job/descriptor evidence and repeat after the fixture's owned restart. The test is about absence of an effect: a request accepted into the journal but left pending is not equivalent to HTTP rejection or completed work.

This closes the proposed forwarding path only while endpoint retirement remains effective; it does not itself authorize opening general ingress or prove that work already running finished. Hold the transition gate and fence producers before counting, and independently resolve or quarantine any accepted work. [Operations position](ops-position.md); [Restate versioning](https://docs.restate.dev/services/versioning).

## 2. UID 2004 fixed admin operation

Agree. A root-owned, fixed operation launched by PID1 as the trusted journal UID 2004 is a practical admin path if the actual socket and its ancestry remain private and the operation's arguments, request, target and descriptors are not caller-controlled. Require bounded output and root-owned durable intent and receipt. Verify actual credentials, capabilities, no-new-privileges, environment, unit identity and socket path/mode/ACL in the pinned fixture; also test accidental inherited and passed descriptors. Do not relax the data directory, add a shared group, or grant network administration merely to make root traverse it.

This is root-mediated execution under a trusted UID 2004, not proof that the socket authenticates UID 0 or protection against a compromised journal account. Restate's self-hosted admin has no application-level authentication, so direct UID 2000 access must fail independently of the root gate. [Server security](https://docs.restate.dev/server/security); [Linux research](linux-research.md).

## 3. One bounded fixture

Agree. One fresh factory-owned namespace and data root with pinned Restate, two synthetic SDKs and fixed probes is sufficient for the first decision. The root-provided configuration dump shows that `RESTATE_ADMIN__LISTEN_MODE=unix` is parsed into the intended admin setting; it is not yet proof of binding, access permissions or surviving restart. Prove those at runtime, plus no TCP admin, normal required ingress connectivity, positive 8080 forwarding before retirement, failed direct and forwarded effects afterward, pinned/queued/unpinned classification, exactly one non-force registration with lost-response reconciliation, and preserved history after the owned restart. A behavioral positive control must precede every conclusion based on zero. Exact owned resources alone may be cleaned up, and unknown outcomes remain retained.

No reboot, destruction of the existing namespace, or live unit retirement is needed to decide the fixture. Those remain separate production gates. [Pinned admin configuration](https://github.com/restatedev/restate/blob/v1.8.0/crates/types/src/config/admin.rs); [moderator round](moderator-round1.md).

## 4. Live cutover conditions

Agree with the proposed closed intent, recoverable journal backup, preservation of all deployment histories, full old endpoint and socket retirement, restart-safe refusal, exact SDK5 attestation, one registration receipt and all-history replay. The decisive count comes only after the independent fence is established and rechecked. A nonterminal old invocation may be labeled **retained unavailable quarantine**, never drained, and it must block ordinary completion wherever its unresolved effect could overlap new admission. Partial admission requires an actually enforced and tested scope separation; it cannot be inferred from separate task IDs alone.

After a lost registration response, read-only reconciliation must identify the one server-minted deployment and its exact plan binding; ambiguous outcome keeps the marker closed. Never retry the POST, silently cancel or reroute old work, delete history, or revive an ungated endpoint. A positive fixture result selects a conditional direction; it does not establish production acceptance or approve promotion.
