# Native launcher private-directory access amendment

Mode B follow-up within the authorized OS-supervision review. Decision pending
focused security, Rust operations and contrarian reviews; no fresh model dispatch
is authorized by this brief. Retain the earlier closed generation and reservation.

Actual evidence: the first root native launch failed before its launch lock,
deadline or create intent. The original stderr was discarded, so its sole cause
is unproved. The bridge/static readiness used CAP_DAC_OVERRIDE. Native root with
empty capabilities got EACCES on the UID2000/0700 callback and fence directories;
the exact same bounded read-only probe with only CAP_DAC_READ_SEARCH succeeded.
Receipt: `/tmp/sfactory-identity-admin-1pdillk2`.

Compare (A) keep launcher cap-empty and redesign ownership/descriptor handoff;
(B) give only the root native launcher CAP_DAC_READ_SEARCH in bounding/ambient
sets, retaining NNP and all worker/relay/broker/brake capabilities unchanged;
(C) broad DAC_OVERRIDE or added ptrace privileges. C is rejected. B is proposed
because this fixed root-only launcher already controls the root Docker socket,
accepts only a fixed phase plus canonical generation and pins its code/recipe.
A would require a separately tested callback ownership and evidence handoff change.

CAP_DAC_READ_SEARCH also permits open_by_handle_at and linkat AT_EMPTY_PATH; it is
not a filesystem sandbox. Root/Docker administrators remain in the trusted base.
It adds no human presence/MFA claim and is never given to model/worker services.
No arbitrary path/command/env is accepted at the launcher boundary. Admission must
still require root catalog, one-use grant, independent direct-kernel deadline,
full IDs, permanent closure, fixed mounted files and manager-based attestation.

Required evidence before adoption: exact native capability/NNP check; protected
registry and process attestation; read-only helper/unit/input preflight in the
same native context; ordinary operator brake active independently of the launcher;
late-start/unknown-outcome fencing; no re-open of the failed generation. Broader
owner/daemon/host-loss gates are retained and this amendment does not certify them.

Primary sources: [Linux capabilities manual](https://man7.org/linux/man-pages/man7/capabilities.7.html)
and [systemd257 execution settings](https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html#Capabilities).
Reviewers must inspect the code and actual evidence; recommend A/B or identify a
concrete blocker. Keep recommendations distinct from unrun integration proof.

Security review found a concrete pre-existing callback pathname race: UID2000
owns the callback directory and can replace its socket before Docker resolves the
bind path. Prefer a revised A: root:2000 mode0710 callback parent, root-created
socket, control service uses its O_PATH traversal; UID2000 gets search but no
write and UID2001 cannot traverse the host parent. Native root can then inspect
this callback without extra capabilities. The launcher does not need to read the
UID2000 private fence directory; postrun evidence custody remains separately scoped.
This would require exact versioned backups and reviewed atomic updates of the
owned helper/package metadata checks, fresh preclaim plan, and actual cap-empty
native readiness plus UID2000 positive/UID2001 denial controls. No currently
running shared service or old generation would be changed. Review this A against B.

Outcome: [conditional revised-A consensus](2026-10-30-native-launch-read-access/consensus-plan.md).
All three reviewers agree after the security finding; implementation and actual
permission/lifecycle/upgrade gates remain open. B is not adopted.
