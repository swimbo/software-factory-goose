# Public Root gateway lifecycle qualification (U4)

Date: 2026-11-05 (America/New_York). Source: `d843be3ddd57a7a2e04d7c593444e49f49aeecf4`, branch `codex/late-phase9-verification`. [Machine record](2026-11-05-gateway-root-lifecycle.json) contains source hashes, full commands, public drivers/generator, terminal receipts, failed controls, completed review and parent audits.

## Result

The genuine Root constructor and broker-authenticated public start own the unchanged qualified gateway executable, sealed bootstrap configuration, bounded post-exec readiness and retained child. Root verifies exact grant/scope/configuration/process/socket bindings before worker traffic. Consumed intent prevents relaunch; failed readiness or lost authority fences and joins the child. Schema5 binds only the reviewed broker/capture UID mappings across creation, inspection and bootstrap. Tools remain Goose-owned.

Source qualification is complete for U4. Handed-socket cleanup remains denied. Candidate remains disabled, benchmark 0/120. Public fixture workers were exercised; production deployment, activation, permission changes and paid inference were not performed.

## Verification

- Full configured harness: **290 total: 283 passed, 7 skipped**, 55.802s. Focused gateway suite:41 total: 40 passed, 1 skipped. Ruff and diff checks pass.
- All five final native cases use gateway SHA `ed3f47367f4da8400685e26d4a2a0acea1f05d2c7c73cb3ea6caff87be3468a7`, final supervisor SHA `05b9a8ef122abe339a7ed518a54945c0114c6c6f6cb66ce23fca3bea303bb7e5`, and current NUC x86-64 helper filter/mappings. No Go source or executable rebuild was needed; Bifrost remains `f174154`.
- Parent independently verified final source bytes, boot and exact cgroup identities, gateway PID/start-tick absence, empty frozen cgroups, socket inode/owner/mode preservation, owner-revocation/fence receipts and non-running Docker workers. All cases have provider HTTP0. Earlier failed/unknown resources remain preserved.

| Case | Fixture exit | Start HTTP | Observe HTTP | Worker receipt |
|---|---:|---:|---:|---|
| positive | 0 | 200 | 200 | yes |
| ready-reader-closed | 0 | 503 | — | no |
| ready-pipe-full | 0 | 503 | — | no |
| gateway-exits-during-create | 0 | 503 | — | no |
| gateway-exits-before-observe | 0 | 200 | 503 | yes |
| counterfactual | 1 | 200 | 503 | yes |

A zero fixture exit means its expected success or refusal assertions passed. The counterfactual exit1 is the required precise assertion failure, not setup failure. During-create loss leaves a created Docker object without starting it; before-observe loss starts the fixture worker, then actual observe refuses and fences it. Neither reports terminal cleanup success.

## Review and fixes

Five simplification lenses completed; one shared role-map helper replaces duplicate construction and redundant internal comments were removed. Proof tests were preserved. The completed eight-lens code review returned one independently validated P2: a gateway could exit or reach its shorter frozen deadline during Docker preparation, yet worker start could proceed. Root now retains the returned process and rechecks exact launch/peer identity, liveness and frozen deadline immediately before Docker create/start and in running-worker observation. Any failure invokes the existing revoke/fence path.

The new source regression failed all four intended assertions before the fix (exit/expiry at image/create boundaries), then passed. Native controlled old-source comparison changes **only** supervisor05b9 to reviewed35b8; the old source returned start200 with a worker receipt after gateway death, failing the exact expected503 assertion. The fixed source refuses. Actual running-worker observe has both valid and gateway-loss coverage. Finding #1 and the observation testing gap are resolved; no U4 actionable finding remains.

The fresh configured Claude/acpx attempt failed before egress with `Internal error`. Local adversarial fallback completed; no independent cross-model result or code egress is claimed. The full review and resolution are embedded in the machine record.

## Serialization and fixture constraints

An earlier actual-command refusal exposed Python reserialization of Go `json.RawMessage` policy data: number spelling, object order and escaped strings changed the typed hash. A proof-first regression now protects structural extraction of every hash-pinned template top-level value fragment; Root encodes its own metadata separately. Go integrity checks and hash domains remain unchanged. Actual Root grant SHA remains distinct from the saved wallet scope digest.

Native setup uses a fresh ext4 root, private pivot, host PID/cgroup views and the same absolute host-visible owned paths. A paired probe measures chroot `CLONE_NEWUSER` refusal (`EPERM`) and private-pivot success; this matches [Linux unshare documentation](https://man7.org/linux/man-pages/man2/unshare.2.html). Writable fixture filesystem state is limited to the owned base and exact gateway directory; setup also exposes the scoped systemd, Docker and cgroup interfaces. Pre-existing gateway inode metadata is checked unchanged. Reviewed fixture setup capabilities include `FOWNER` for the existing broker-owned relay hardlink. These setup privileges do not establish production Root confinement or provisioning approval.

The registry/catalog/owner inputs and SQLite contents are public fixtures. U4 proves actual Root/executable ownership, not the full real wallet/capture exchange. U5 must qualify descriptor/namespace custody, handed-socket retirement and outage/daemon/host-loss behavior; U6 must complete the joined protected rehearsal, including a second successful exchange proving warm/paid readiness reuse with a new acquired owner. Supported affordable provider bounds and reviewed real principal/model/key configuration still gate paid admission.
