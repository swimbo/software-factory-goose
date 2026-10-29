# Authenticated two-root brake fixture

On the NUC, `nuc_batch_authenticated_brake_spike.py` built the locked Rust watchdog fixture in an isolated temporary directory with two build jobs and debug information disabled. It created two uniquely labeled disposable roots in the existing worker slice and verified the slice was populated.

A networkless, nonroot, capability-dropped client with the wrong UID or wrong key received 403; a valid peer and key with an unknown target received 409. While the batch lock was deliberately held, the first valid stop timed out with 503 and the next returned 202 pending. The cleanup helper had durably closed admission before obtaining the lock. Once released, an authenticated retry returned 200 only after both exact owned roots were removed and the same cgroup inode reported `populated 0`. Both roles refused later starts. Client containers and the isolated build were removed after verified cleanup; no shared service was stopped.

This is a fixture with a temporary peer key and trusted same-UID host code. It does not prove that the brake remains independent of an actual relay or gateway outage, that host manager or Docker daemon loss is recoverable, that the same UID cannot bypass advisory coordination, or that production operator identities and containment are established. No live provider request was made.
