# Research brief: Rust operations

Research date: 2026-10-26. Perspective: minimize operational machinery while making authentication, socket ownership, restart behavior, and brake independence testable. No authentication implementation was changed. Evidence grade: **ADEQUATE for choosing a spike; insufficient for enabling privileged operations**.

## Evidence summary

1. The actual lockfile pins Axum **0.8.9**, Tokio **1.53.3**, reqwest **0.12.28**, hyper **1.12.0**, and hyper-util **0.1.21**. Claims below were checked against those installed sources, not inferred from latest documentation. Source: [Cargo.lock](/Users/bo/code/software-factory-goose/clean-room/Cargo.lock).
2. Axum 0.8.9 implements its `Listener` trait directly for Tokio `UnixListener` under Unix. Existing `axum::serve` can therefore serve the current router on a socket without a custom Hyper accept loop. [Official API](https://docs.rs/axum/latest/axum/serve/trait.Listener.html), retrieved today, shows 0.8.9; installed `axum-0.8.9/src/serve/listener.rs:45` confirms it.
3. Tokio 1.53.3 exposes `UnixStream::peer_cred() -> io::Result<UCred>`. Its macOS implementation obtains PID using `LOCAL_PEEREPID` and UID/GID using `getpeereid`, and returns errors when those calls fail. This is directly supported on the target platform. Source: [installed macOS implementation](/Users/bo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.53.3/src/net/unix/ucred.rs:294). [Online API](https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html#method.peer_cred) currently reports 1.54.1; it is corroboration, not the version authority.
4. Axum's upstream Unix-socket example passes peer credentials into `ConnectInfo` using `Connected<IncomingStream<UnixListener>>`. It uses `unwrap()` and unconditionally removes the socket path, so it demonstrates API wiring, not a safe production lifecycle. [Upstream example](https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs), retrieved today.
5. Existing reqwest 0.12.28 already supports `ClientBuilder::unix_socket(path)`. Its documentation says this overrides TCP/proxy options and bypasses DNS lookup. The CLI does not need another HTTP client library. Source: [installed client builder](/Users/bo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/reqwest-0.12.28/src/async_impl/client.rs:1796).
6. Socket-file mode alone is not a portable authentication guarantee: Linux's manual explicitly cautions that other systems may ignore those permissions. Require peer UID verification and a protected parent directory; verify macOS behavior rather than importing Linux assumptions. [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html), retrieved today.
7. Axum's graceful shutdown waits for connection tasks to finish. It is not an emergency process-kill guarantee. A hung main process needs an independent watchdog; a graceful shutdown signal inside that process cannot meet that condition. Source: [installed shutdown implementation](/Users/bo/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/axum-0.8.9/src/serve/mod.rs:300). The watchdog conclusion is engineering inference.
8. OWASP calls for transaction authorization checked at execution, limited validity, and unique credentials per operation. This supports binding approval to task, candidate SHA, action, reason, expiry, and a consumed nonce; transport authentication alone does not authorize a particular merge. [Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html), retrieved today; publication date unavailable.

## Option matrix

| Option | Support / operational burden | Risk and fit |
|---|---|---|
| Loopback bearer | Existing HTTP clients; requires token creation, storage, rotation, redaction | Useful transitional transport, but another secret lifecycle and no proof of human intent. Loopback alone authenticates nobody. |
| Owner-only Unix socket plus peer UID | Supported by pinned server/client; requires protected directory and safe restart rules | Best local fit if worker identity differs. UID identifies an OS principal, not a human or MFA. |
| OIDC/device flow | Additional issuer, browser/device interaction, validation and outage policy | Potential later multi-user direction. No provider selected or verified here; not justified as today's dependency. |

## Unknowns and smallest spike

The deployment has not demonstrated distinct operator/worker identities, durable one-time authorization consumption, or a watchdog with independent authority. A second file-readable secret under the same compromised identity is not strong separation.

Build an isolated local spike using the pinned dependencies: protected temporary directory, Unix listener, `ConnectInfo` carrying a fallible credential result, reqwest socket client, owner accept, mismatched configured UID reject, and credential-read failure deny. Test duplicate start, existing regular file, symlink, stale socket, restart, and shutdown cleanup without deleting another process's socket. Synthetic UID mismatch is useful but does not replace a real second-UID test.

Next prove a mock privileged transaction rejects expired/replayed/changed-SHA approvals across restart. Separately freeze or terminate the main service and demonstrate the independent brake kills and reaps a harmless child process group. Keep privileged routes disabled until these checks pass.

## Preliminary recommendation

Choose the Unix-socket spike. Keep machine authentication separate from transaction authorization, and make the watchdog a separately supervised process. Do not claim human presence, MFA, restart durability, or brake independence from transport tests alone.
