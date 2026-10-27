# Gateway environment proxy control

The gateway HTTP client now disables environment proxy discovery. A synthetic loopback proxy received one request before the change; after it, the child-process test observed no proxy requests and the direct mock gateway received the expected traffic. The test sets proxy variables only in its disposable child. Separate synthetic controls check that the admin credential reaches only governance, the virtual key reaches only inference, neither goes to the reservation endpoint, and 307 redirects do not forward either credential to the redirect destination. `cargo test --locked --offline -p control-plane --all-features --lib gateway::tests::` passed 15 tests.

This is not OS-level egress enforcement, trusted base-URL validation, a daily cumulative ledger, real provider authorization or the Goose tool-conversation protocol. No external provider or real credential was used.
