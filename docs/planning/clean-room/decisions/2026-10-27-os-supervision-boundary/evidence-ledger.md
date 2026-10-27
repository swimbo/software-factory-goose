# OS supervision evidence ledger

Reviewed 2026-10-27 by macOS security, Rust operations, and contrarian recovery reviewers. **Evidence grade: INSUFFICIENT for a production containment decision.** The reviewers independently researched the brief; the debate workflow stops at the evidence ledger and spike plan because the decisive containment and recovery properties are unproved. A production choice is not implied.

## Questions

Which OS boundary can bind approved launch and separate identities to containment, an independent stop, and safe recovery across blocked launch, process escape, owner failure and lost acknowledgement? What negative controls establish that boundary without affecting unrelated workloads?

## Sources and verified facts

| Source | Type and date | Finding | Reviewer |
| --- | --- | --- | --- |
| [Apple permissions](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Permissions/Permissions.html); [secure privilege changes](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/AccessControl.html) | Apple archived documentation; checked 2026-10-27 | Cross-user signaling and arbitrary identity transitions require appropriate OS authority; credential changes must be checked. | Security, operations |
| [Apple secure helpers](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/DesigningSecureHelpers/DesigningSecureHelpers.html) | Apple archived documentation; checked 2026-10-27 | Minimize privileged code and separate duties. This does not prove complete-family containment. | Security |
| [Apple setsid](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsid.2.html) | Apple manual; checked 2026-10-27 | An eligible process can create a new session and process group; a group-only kill is not a universal descendant boundary. | Security |
| [Rust Child](https://doc.rust-lang.org/std/process/struct.Child.html); [Unix CommandExt](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html) | Rust official documentation; checked 2026-10-27 | Child drop does not wait or kill; `try_wait` can reap. Identity setup and `pre_exec` have specific ordering and safety constraints. | Operations |
| Local `man launchd.plist` | Host manual; checked 2026-10-27 | System-domain jobs support configured identities and group-oriented cleanup. This is not proof of containment after `setsid` or independent stop of a hung launch. | Operations |
| [Apple Virtualization](https://developer.apple.com/documentation/virtualization/vzvirtualmachine); [requestStop](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/requeststop%28%29?changes=_1_6) | Apple API documentation; checked 2026-10-27 | VM lifecycle APIs distinguish stop from a cooperative guest stop request. Documentation reviewed did not establish independent takeover of an owner-held VM after the owner hangs or dies. | Operations, recovery |
| [Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html); [systemd kill](https://www.freedesktop.org/software/systemd/man/248/systemd.kill.html) | Kernel and systemd documentation; checked 2026-10-27 | Guest cgroups can group and terminate processes subject to migration authority. They do not establish macOS host isolation, egress control or owner-failure recovery. | Recovery |
| [Local watchdog evidence](../../verification/2026-10-27-watchdog-spawn-broker.md); [family evidence](../../verification/2026-10-27-watchdog-family.md); [actual Goose lifecycle](../../verification/2026-10-27-goose-broker-lifecycle.md) | Disposable same-UID fixtures, 2026-10-27 | Current broker stops tested owned groups but has no proved escaped-descendant, blocked-spawn responsiveness, cross-UID authority or crash ownership recovery. | All |

## Options and unresolved evidence

| Option | Supported direction | Unresolved blocker |
| --- | --- | --- |
| Minimal privileged native helper behind separate nonroot frontend | Small privileged surface could own identity transition, wait and signal. | No verified persistent containment for escaped descendants, hung spawn, restart or independent stop. `launchd` alone does not close these gaps. |
| Dedicated VM per family, host-owned independent brake | Whole-guest stop is a plausible containment boundary; guest cgroups could supplement it. | Owner hang/death, independent control, VM teardown, storage/network denial, recovery and operating costs are not proved. |
| Existing same-UID group broker | Useful test harness and negative-control baseline. | Cannot satisfy distinct identities or complete hostile-family containment; not a production candidate on current evidence. |

There is no contradiction requiring a forced vote: reviewers agree that a supervisor is not itself a containment proof and that a VM is a test candidate rather than a proven remedy. The contrarian emphasizes the operational cost and separate VM-owner failure boundary; the other reviewers agree that neither can be omitted. No evidence found proves a macOS equivalent of a durable cgroup-wide kill for arbitrary escaped descendants. Do not restore numeric PIDs or PGIDs as authority.

On this host `kern.hv_support` reports 1 and `xcrun --find swift` succeeds; neither establishes Virtualization entitlement, bootable guest availability, ownership recovery or operational safety. No VM, account, service or privileged helper was created by this review.
