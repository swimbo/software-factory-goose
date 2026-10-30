# Exact root authorization for the private journal handler

Implementation review found that namespace isolation does not distinguish UID0
from trusted control processes already sharing the private Restate namespace.
The public Unix ingress authenticates UID0, but a direct HTTP call to the journal
must not manufacture a new root-attested result. This is an implementation of
the consensus bypass-denial requirement, not a change to human approval scope.

Proposed minimal mechanism: after validating the immutable evidence, a root-only
publisher creates and fsyncs a per-generation authorization file containing the
exact task/generation and canonical finalization-request SHA256. The file and all
ancestors are protected against non-root modification; it is single-link,
root:root0444, no ACL, bounded strict JSON, opened without symlinks. Its pathname
is derived only from the configured canonical generation under the fixed
finalization directory. The root request/evidence stay0600; no key is added.

Before any same-object decision, the journal reads this fixed authorization in
a durable read step and requires an exact request digest and scope match. No
authorization file, unsafe metadata, different body or different scope denies.
A direct client can at most deliver an identical root-authorized record; it
cannot choose another outcome or authorize promotion. Publishing the file is
the root authorization act. The file is never overwritten, deleted or reused.
The permanent reservation and identical/changed-replay rules remain unchanged.

Alternatives: a root-private signing key with SDK public-key verification gives
similar exact-payload authorization but adds key lifecycle/dependencies; a port
firewall cannot distinguish HTTP methods sharing the existing journal ingress;
trusting network membership alone does not enforce the intended boundary.

Questions for the three approved reviewers: is the exact protected authorization
file sufficient under the existing root/manager/journal-code TCB, and does
publication correctly define authorization timing? What controls must precede
publication and what tests distinguish a real bypass from identical authorized
delivery? No implementation or activation is authorized by this brief itself.
