# Contrarian usability research — operator authentication

Research date: 2026-10-26. This is evidence and options, not an adopted design. The present scope is one human operator on one macOS host. Distinct worker identities and an independent emergency brake remain requirements.

## Verified facts

**U1 — Local identity can avoid token handling.** Apple's `getpeereid` documentation describes kernel-reported effective user/group credentials for Unix-domain peers, captured at connect/listen time. Both client and server can inspect the other side. This provides a usable building block for checking the intended service and operator without copying secrets. It identifies a process credential, not human presence or a second factor. [Apple manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html). Tokio exposes `UnixStream::peer_cred`, so a Rust CLI need not invent its own wire identity field. [Tokio API](https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html#method.peer_cred).

**U2 — Bearer convenience carries possession risk.** RFC 6750 defines bearer authority through possession and requires protecting tokens against disclosure and transport interception. Its recommendations include short token lifetimes and avoiding URI exposure. A local CLI token would therefore need deliberate storage, delivery, rotation and redaction, even if the endpoint is loopback. Two files holding different bearer strings do not establish independent human factors. [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html).

**U3 — Device flow is usable but not free of phishing.** RFC 8628 supplies a verification URL, user code, expiry, approval/denial and polling behavior. It recommends understandable code presentation, confirmation of the correct device, and an expiry long enough for the person to finish. It also explicitly describes remote phishing risks. Choosing OIDC/device authorization does not itself decide MFA policy or bind a factory promotion to a particular commit. [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html).

**U4 — Approval needs meaningful action presentation.** OWASP recommends presenting significant transaction data, distinguishing sign-in from action authorization, server-side enforcement, unique per-operation credentials, expiry, and invalidation when transaction data changes. It also calls for atomic single use. Applied here, the user should see the task, repository, target branch, old/new revisions, evidence verdict and expiration before approval. This application to Git promotion is our inference, not an OWASP implementation prescription. [OWASP transaction authorization](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Transaction_Authorization_Cheat_Sheet.md).

## Options and usability tradeoffs

A peer-checked Unix socket is attractive for routine local commands: no repeated login, no clipboard token, and no remote service dependency. Setup complexity moves into installation, ownership, directory modes and clear recovery messages. Crucially, a worker running as the operator cannot be distinguished this way. The initial CLI must diagnose that condition and refuse enabling mutation.

A loopback bearer is familiar to HTTP tooling, but makes secret handling a daily operational concern and encourages environment-variable inheritance. It may be appropriate for a deliberately scoped integration later; it is not obviously simpler for this single-host operator.

OIDC can centralize identity and MFA and makes sense when there are several operators or remote access. For this MVP it adds enrollment, browser interaction, provider availability and recovery work. Keeping it as a later adapter avoids making an emergency stop depend on an identity provider.

My contrarian concern is confirmation fatigue: making every status/read command require step-up would train the operator to dismiss prompts. Reserve explicit transaction authorization for consequential mutations, with one concise receipt and an unambiguous action verb. A preview must never itself execute. An expired preview should preserve its readable explanation while requiring fresh authorization.

## Proof gaps and bounded spike

Before choosing, demonstrate an owner-only socket in a private temporary directory with kernel peer checks, including rejection of a separately provisioned worker UID and a forged claimed UID. Test socket replacement and stale-socket handling without deleting arbitrary paths. This cannot be proved by two processes sharing the current operator UID.

For approval, show one task/SHA-bound challenge, then test replay, expiry, wrong task, changed candidate, changed destination and simultaneous submissions. Measure whether the display makes the exact target obvious; do not call typed confirmation MFA.

Finally demonstrate emergency stop while the main service and identity provider are unavailable. The brake must have its own verified authority and process control. Its CLI should immediately distinguish “request received” from “worker process group terminated.” None of these spikes authorizes live deployment or credential provisioning.
