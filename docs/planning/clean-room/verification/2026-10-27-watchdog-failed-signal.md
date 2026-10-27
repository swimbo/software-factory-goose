# Watchdog failed-signal ownership

A test injected `EPERM` at the owned group-signal boundary. Before the fix it failed: the record was marked attempted before the signal outcome, allowing the stop loop to reap its leader even when the group signal failed. Reaping would release the PID ownership anchor and prevent a safe subsequent signal. The test used only an owned disposable sleep process and restored its state before cleanup even on the expected failure.

The signal routine now marks the group eligible for reaping only after a successful signal or `ESRCH`. Other errors keep the owned child handle and return an unresolved outcome. A retry first revalidates child ownership and group identity; a test also verifies the signal callback is not invoked after the child is reaped. Persistent permission failure can leave the handle and group unresolved; it is not reported as a successful stop.

On macOS, the stricter rule initially caused both synthetic capture fixtures to fail because XNU may return `EPERM` for a zombie-only group. For the **fixture-only capture path**, a complete positive `proc_listpids` enumeration containing exactly the observed unreaped zombie permits reaping, followed by a group-absence observation. Enumeration and reaping are not atomic, and this accommodation is not used to establish production containment.

Final local checks passed: 25 watchdog tests, strict all-target/all-feature Clippy, and the blocked-pre-exec canary. This does not prove escaped-descendant containment, signal authority across UIDs, recovery after watchdog death, or a production independent brake.
