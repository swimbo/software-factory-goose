# NUC Rust gate fixture — 2026-10-27

On `hermes-control`, Debian 13 x86_64, Linux 6.12.107 and Rust/Cargo 1.98.1, the unregistered Rust gate passed its focused Linux tests and a real disposable Restate journal replay. The local account was UID 1000; the positive peer test uses that same UID, while the negative test expects a different UID. No additional account was created.

The isolated build used `/tmp/sfactory-gate-linux.X4ZjF1LB` on tmpfs, with its own Cargo home, target directory, source copy and journal state. The checkout's lockfile-selected public crates were copied into the isolated Cargo home; two missing Linux crates were downloaded there. Debian `libssl-dev`, `pkgconf`, `pkgconf-bin`, and `libpkgconf3` were downloaded and unpacked there, not installed; headers linked to the existing OpenSSL 3.5.7 runtime. Restate 1.8.0 was copied from the already present `restatedev/restate:1.8.0` image via a temporary stopped container, then run as a task-owned native process with random loopback ports and a task-owned state directory. A 0700 temporary directory under `/home/bo` held the 0600 relay socket and was removed after the test. No database, standing service, worker, provider credential, or production endpoint was used.

Results and the exact fixture script are in [the accompanying evidence directory](2026-10-27-nuc-rust-gate/):

- `worker-tests.log`: 11 passed, including actual Linux ext4 access/default ACL insertion and rejection, symlink rejection, and socket identity replacement denial.
- `gate-tests.log`: seven passed and one real-journal test intentionally ignored in the ordinary run.
- `gate-replay.log`: the ignored real-journal test passed with kernel peer credentials, fixed synthetic loopback provider, connection/header bounds, forged requests, concurrent/replayed admission, and revocation.
- `clippy.log`: locked all-feature, all-target control-plane Clippy completed with warnings denied.

The Linux ACL implementation permits only ext4 and fails closed on either POSIX ACL xattr or any inspection error. This evidence does not establish protected distinct-account provisioning, NFS or other filesystem support, production catalog provenance, deployed Goose/Bifrost routing, or isolation against a compromised host. A begin-before-revocation operation can still reach the provider. Existing Hermes dashboard, gateway and Docker services remained active according to the separate preservation check.
