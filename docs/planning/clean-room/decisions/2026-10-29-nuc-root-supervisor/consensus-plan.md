# Consensus — guarded NUC root supervisor implementation

Three reviewers, primary-source research, real owned NUC discriminating canaries, position papers and one concession round. No HIGH design disagreement remains. Root moderated because a specialized moderator tool type is unavailable. Evidence is ADEQUATE for guarded implementation and insufficient for production acceptance until the tests below pass. User authorizes scoped host administration through existing Docker permission.

## Selected boundary

Use narrow root-owned systemd-supervised launch/stop authority outside Docker and every workload subtree. Retain the verified pinned Docker worker configuration where tested. Root-owned immutable catalog binds opaque task/generation, authoritative claim/lease, exact binary/image/argv/mount/env/role constraints and cgroup identity. No peer selects arbitrary paths, PIDs, commands, units or Docker arguments. Record/fsync intent before effect; create stopped, validate/persist exact ID and seal before start. Permanently close admission before stop. Unknown effects stay closed/frozen; startup validates/reconciles durable root state before admitting anything.

Use a separately supervised nonroot brake frontend with separate stop bearer and a root backend that authenticates that principal and permits only catalog-owned stop operations. Keep it available without the control plane, Restate, gateway or Docker client. Freeze+kill+same-inode empty are separate facts from reconciled daemon closure. The pinned Moby full-ID removal fence is conditional on source/daemon identity and complete same-subtree checks. No thaw/removal on unknown outcomes; worker cannot migrate, write cgroup controls, reach the daemon/control network or obtain either operator credential.

## Principals and operator scope

Create locked nonlogin control, worker, evaluator, brake-frontend and journal identities. Existing bo UID1000 is the human operator relative to those distinct identities, preserving existing SSH keys/groups/sudo configuration. Ordinary host CLI approval/stop must not need Docker or sudo. Root and existing Docker administrators remain trusted. O4 expressly disclaims MFA and resistance to same-UID compromise; do not introduce an unapproved login key or impossible protection against a bo/Docker-root compromise as a new MVP blocker. Nonetheless, approval bearer substitution for brake, wrong peer identity and service/worker access to brake material must be denied and tested.

## Installation and integration sequence

1. Install reviewed additive identities/root directories only after exact PLAN review, safe ancestors/ACL/UID/GID/orphan-ownership checks, per-action durable records and existing account-entry preservation checks. Retain partial installs; never restore global account files or overwrite existing paths. Do not enable service admission in this step.
2. Install root-owned pinned supervisor/brake binaries and root-owned socket/catalog configuration. Use exact new factory units, fixed constraints and conservative rollback. No shared Docker/Bifrost/Hermes/Stapled restart, host reboot or old-resource mutation.
3. Test actual helper owner-loss/restart around intent/create/start/closure, held/lost replies, forged/replayed/wrong-role calls, catalog/cgroup substitution, setsid descendants and denied migration. Prove independent stop with a deliberately unavailable disposable Docker endpoint. Use a positive first-operation marker and a deliberately bad control; preserve limits of finite observations.
4. Deploy the private runtime using new exclusive journal state, isolated service network namespace and root-created authenticated UDS. Validate namespace/roles/catalog/source evidence, private SDK registration and replay; workers must not bypass qualification through direct scheduler/admin ingress. The new durable catalog-bound intake→queue→claim code connects existing components; a single preauthorized greenfield recipe does not implement general multi-task decomposition.
5. Connect claim-bound actual Goose/provider dispatch, exact receipt, isolated wall and action-bound human promotion. Preserve prior successful candidate and all ambiguous fences. Test the complete intent→merge path and remaining story/gate matrix before acceptance.

## Alternatives rejected and limits

Docker-only guardian/operator cannot satisfy daemon-independent stop. An unsupervised custom root daemon adds lifecycle risk without solving queued Docker work. Native clone3(CLONE_INTO_CGROUP) remains an unselected fallback requiring its own namespace/isolation proof, not a silent replacement.

No real daemon/systemd-manager/host interruption is authorized. Test a task-owned isolated equivalent or simulations with exact limits; do not claim power-loss/host recovery from fsync or a process SIGKILL. If a required property remains unproved, retain that named gate and continue remediation, never manufacture acceptance. The experiment's no-cap waiver does not alter production monetary defaults. No promotion or overall project completion is granted by this consensus.
