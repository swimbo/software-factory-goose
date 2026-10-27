# Holdout runner process ownership

The fixture runner previously awaited the scenario leader with `child.wait()` and then
signalled its numeric process group. Reaping can release the PID before that signal, so
another process group could acquire the same number. It now uses the evaluator's existing
`OwnedGroup` WNOWAIT implementation: the owning task observes the leader without reaping,
signals the group while ownership is retained, and only then reaps. It refuses to signal
when ownership cannot be verified. Stdout, stderr, stdin and runtime remain bounded; error
output remains opaque. Cancellation of the async caller signals a flag to the blocking
owner, which performs the same cleanup; cancellation is not a claim of synchronous cleanup.

Three tests exercise actual children: a leader exits leaving a delayed descendant, direct
cancellation, and aborting the async caller after the child starts. No delayed child writes
its marker. This is a behavior control for the new owner, while the original reaping hazard
was established by source inspection rather than inducing a recycled PID. The evaluator
all-target offline suite passed (59 tests), including real Seatbelt holdout fixtures, and
strict evaluator Clippy passed. These same-UID tests do not prove cleanup after owner death,
escaped process groups, separate-UID isolation, or production activation.

Follow-up: the deadline now starts before blocking-pool queueing, and an expired or
canceled queued operation returns without spawning. A single-thread blocking pool test
uses a pre-exec pipe canary: the canceled queued task spawned before the fix, while neither
canceled nor expired queued work spawned afterward. Expiration returns Incomplete while
the pool remains saturated. The fixture prefilter stops on the first Unavailable result;
an end-to-end two-scenario timing control failed before this change and passed after it,
while an ordinary failed assertion still produces Rejected. The timing control demonstrates
the tested fixture behavior, not a scheduler-independent proof of process absence.
The cancellation/deadline check and OS spawn are not atomic: cancellation in between is
in flight, and the owning task requests asynchronous group cleanup. No completed pass is
reported for that result. Full evaluator all-target tests: 61 passed; strict Clippy passed.
