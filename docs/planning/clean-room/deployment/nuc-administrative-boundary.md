# NUC administrative boundary — decision required

## Observed access

`bo` is UID1000 and belongs to the Docker group. Noninteractive `sudo` is unavailable. There are no host passwd entries for the fixture UIDs1001/1002. Existing Docker, Hermes dashboard/gateway and Stapled resources must be preserved. Docker live restore is disabled; changing or restarting the shared daemon is not authorized by this proposal.

The current experiment proves a live model-generated, isolated, hash-bound candidate. It does not provision the separate local operator account selected in O4, establish an independent stop authority during Docker failure, or connect the production factory pipeline.

## Proposed administrative scope

Subject to a reviewed implementation, establish only factory-owned resources:

- Separate local service, worker, evaluator and operator identities, with checked unused UID/GID assignments. No existing account, group membership, SSH key or sudo policy is changed. Do not silently reuse the fixture numeric UIDs or authorize a human login key.
- A narrowly scoped root-owned supervisor outside Docker, authenticated private Unix ingress, an independently usable operator stop channel, and a persistent factory-only cgroup hierarchy. Its catalogue and admission-closure records bind exact task identities; arbitrary PIDs, paths, commands or shared containers cannot be selected by a worker.
- Pinned reviewed binaries under `/usr/local/libexec/software-factory-goose/`, units prefixed `software-factory-goose-`, and root-owned state under `/var/lib/software-factory-goose/` with restrictive permissions. Do not enable admission until provenance, identity, late-launch closure, owner-loss and recovery checks pass.
- Preserve all prior unknown fences and the retained inert created-container reservation. Never remove/start/rename it as part of installation.

Installation must first produce an exact file/account/unit inventory and rollback procedure, check name/UID/path collisions and free space, and refuse partial or ambiguous prior installation. Starting the new supervisor must not restart Docker, Bifrost, Hermes or Stapled. Host reboot or shared daemon-failure testing requires a separately reviewed maintenance window or isolated equivalent; it is not implied here.

## Privilege mechanism needing a human decision

Preferred: an operator-provided administrative session or narrowly approved installer invocation. The existing `bo` Docker permission is also capable of granting host-root authority, but the fixture's permission to create isolated workers does not by itself approve using that power to modify the host OS. Such use requires an explicit choice before implementation/deployment of this boundary.

This document is a scope proposal, not an executable installer or completed deployment approval. No host-root access, host accounts, units or shared-service configuration were changed in preparing it. No password or private key should be sent in chat.
