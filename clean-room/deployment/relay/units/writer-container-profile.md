# Fixed writer profile draft — no container launch authority

The root launcher must bind a pinned writer image digest and the exact created container ID, image, PID and generation cgroup before admitting broker publication. The container's PID 1 is the fixed `nuc_fixed_writer.py` routine, UID/GID 2001, no supplementary groups/capabilities, no-new-privileges, reviewed seccomp, network none, read-only root filesystem, and no Docker socket. It receives only three exact mounts:

- Root-owned generation input directory as `/handoff/input`, read-only; inside the mount directory is root:root 0755 and the root-created request and ready files are root:root 0444.
- UID2001:2001 0755 generation output directory as `/handoff/output`, writable only to the fixed writer; broker accepts only a UID2001:2001 single-link 0644 `result.json` with exact content digests.
- Exact generation candidate worktree as `/candidate`, UID2001:2001 0755, writable only to the fixed writer.

The model container receives none of these mounts, has no broker socket, and cannot select the writer image, paths, argv, container ID or PID. The broker is outside the generation cgroup, while this writer is inside it. The parent generation directories must be root:root 0700 on the host, so UID2001 cannot bypass the read-only input mount through host paths. Exact mount inode/device identity, cgroup membership, image/entrypoint, peer identities, process death, stop racing publication and manager recovery must be verified before any activation. This draft chooses no image digest and performs no launch.
