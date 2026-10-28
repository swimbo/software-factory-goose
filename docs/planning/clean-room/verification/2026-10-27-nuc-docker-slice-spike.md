# NUC Docker worker-slice spike

The NUC's existing Docker engine reports cgroup v2 with the systemd driver, default AppArmor and seccomp, and cgroup namespaces. A local pinned Python image was used with pull disabled. Two runs used only uniquely labelled, task-owned containers: a short-lived anchor in a task-named parent slice and a nonroot worker in its child slice. Containers used `--network none`, read-only root, no user bind or volume mounts, all capabilities dropped, `no-new-privileges`, and bounded CPU, memory and process count. The worker checked its real UID, zero effective capabilities and `NoNewPrivs`; Docker inspection checked no user mounts and no network. No Docker socket or host cgroup was mounted into the worker. The exact full IDs and random label were checked before removing those containers.

A worker child verified its own new session. A pipe handshake required it to survive the kill and reap of its in-container guardian; a no-kill control then produced a delayed marker. The child attempted to write its PID to its visible cgroup root's `cgroup.procs`; both runs got an access/read-only error. This is a real denial of that write, not a comprehensive test of every possible host-cgroup migration route or namespace escape.

For the kill control, the host read the owned Docker process's `/proc/<pid>/cgroup` only to verify its expected container ID and worker slice; it did not signal that PID. An external controller then requested `docker kill`. The independent host observer saw the task-owned worker slice change from `populated 1` to `populated 0` while its parent anchor remained alive; the slice directory inode matched before and after observation and the later marker was absent. The no-kill positive control and two runs succeeded. The observer was outside the worker container. No production worker or unrelated engine resource was changed. This is a Docker-kill control, **not** an automatic controller-loss or outer host-guardian-loss test.

## Task-owned residual slices

All fixture containers were removed. Docker's systemd driver left these automatically generated, fragmentless, root-owned system slices active and empty, with `populated 0`:

- `sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice`
- `sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice`

They correspond to task token `6a2ae9a8ef374a84b94c15a1b1d4d7f0`. The child had zero descendant cgroups and the token-filtered container inventory was empty before a scoped `systemctl --no-ask-password stop` of exactly these two slices. Systemd rejected that stop because interactive authentication is required; no global unit reset was attempted. These task-owned slices remain for an authorized administrator to inspect and stop, child before parent, after rechecking identity and emptiness. They are not presented as cleaned up. The second run reused these exact slices rather than creating more.

## Removal semantics and unresolved proof

The [kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html) says a cgroup without child cgroups or live processes can be removed, even if zombie associations remain; a dying cgroup cannot be repopulated. A candidate future proof could retain the exact protected cgroup identity and demonstrate kernel removal of that same inode after admission is closed, with controls proving workers cannot leave or create work externally. An `ENODEV` read or missing path alone does not establish that chain, and removal does not prove a worker failed to migrate before removal. No removal-based success is claimed here.

The test does not establish strong isolation, Docker-daemon or outer-guardian failure recovery, authenticated independent brake, denied migration to every host target, reliable revocation of engine access, a trusted image supply chain, or containment against kernel/runtime vulnerabilities. Docker-group access grants a broad authority to the host guardian and must not reach workers. Production remains fail-closed.
