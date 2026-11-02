# Gateway pre-exec barrier: isolated Linux replay

On 2026-11-02, the published pre-exec helper was replayed on `hermes-control` in a network-disabled, read-only Docker fixture with separate Root, gateway and broker identities. The helper SHA-256 was `0f25e4b3206115469b188594250a837eb7ad1194d9715372b4f69d1bb65d34b5`; fixture SHA-256 was `9d76e576d276b8a7212b32f1050e73ec4a28a757cb54eea4949cb457100aa61a`. A static synthetic Go target received the bound socket and called listen after release.

The fixture denied a closed gate, changed cgroup inode, changed program digest, wrong gateway group, expired deadline, setuid program, changed socket inode and a `SOCK_SEQPACKET` socket. The released target executed as the expected gateway UID, as observed by the broker via `SO_PEERCRED`. Killing the controller before releasing the gate caused the child to exit without executing the target. A first invocation ran the controller as container PID 1 and was refused by the helper's owner PID check; the passing invocation used a separate shell parent.

This is synthetic evidence only. The process stayed in the fixture container's existing cgroup; cgroup migration, Root launcher integration, real Bifrost bootstrap, credentials and route custody, and post-release owner-loss and descendant cleanup were not tested. No provider calls were made and this does not qualify production admission.
