# Physical-call admission ordering

Concurrent physical calls could receive sequence numbers in one order but reach the broker's sequenced authority check in another. A regression reproduced the overtaking and refusal. Bifrost commit `4b87387` serializes sequence assignment and authorization; calls can execute concurrently once admitted. Waiting is bounded by the existing call limit, cancellable waits fail the capture closed, and sealing cannot report a complete capture while admission is queued.

The full Go schema suite passed under the race detector, including ordering, cancelled-wait and queued-seal tests. Five distinct-UID native exchange and stream scenarios passed, and the updated actual wallet, Root, broker, Bifrost handler, capture and collector fixture passed with a synthetic provider. The exact pinned installer was reconstructed and replayed. The [receipt](2026-11-01-physical-admission-ordering.json) records source hashes and fixture limits. The configured Python harness also passed 230 tests, six skipped, with the pinned QuickJS host and a freshly built normalizer.

These results do not qualify production gateway startup, egress fencing, provider charge bounds, or host and daemon failure cleanup. No paid benchmark calls ran; the candidate remains disabled.
