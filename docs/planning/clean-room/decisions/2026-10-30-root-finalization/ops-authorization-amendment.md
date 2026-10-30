# Operations: exact root authorization amendment

Conditional support. A create-only protected digest authorization is proportionate
for this local trusted-root/SDK-code boundary. It avoids another signing-key
lifecycle while preventing a private-HTTP caller from choosing a different
record. Publication authorizes immediate delivery of the exact payload by any
caller; the later root socket request is not a second approval. This never
authorizes promotion. Root request and evidence remain0600.

Require the root publisher to validate actual fixed-path variant evidence and
the complete reservation/profile binding before creating authorization. The
journal must derive its path from configured canonical generation, check strict
bounded canonical JSON, root ownership,0444 mode, single link, no ACL and safe
ancestors, recompute the digest and compare exact task/generation/request. A
public digest is not caller authentication or protection against compromised
root/SDK code. Identical authorized delivery is acceptable; changed content
denies permanently.

The proposed per-generation root:2000/0440 lock is useful, not overengineering.
Open and validate its fixed inode without links; the publisher takes exclusive
nonblocking flock through file and directory fsync, and the SDK takes shared
nonblocking flock through authorization reading and validation. Missing, busy
or unsafe state is a terminal refusal captured by the durable read step. No
invocation waits for later publication. Non-root service processes must not
replace the lock or publication parents. [Linux flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html)
documents these advisory locks and their descriptor lifetime.

**One crash condition remains unresolved by the lock alone.** If the publisher
dies after making complete authorization bytes visible but before directory
fsync, its descriptors close and the lock is released. A later shared reader
cannot infer that publication durability was acknowledged merely because it
obtained the lock. File fsync also does not establish directory-entry durability.
[Linux fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html).

Before adoption, either provide a concrete recovery/admission fence for that
window, or explicitly allow the trusted SDK read step to finish persistence by
fsyncing the fully validated immutable file and fixed parent while holding the
shared lock. The latter keeps one authorization mechanism and no new key, but
requires readable directory permissions and native proof under the actual SDK
UID, filesystem and sandbox. It changes a nominally read-only lookup into
durability completion and must be stated honestly. Do not add an unchecked
"published" marker whose own visibility has the same crash window.

Test publisher death before/after file fsync and final pathname visibility,
busy-reader refusal, missing authorization followed by a later new invocation,
exact direct delivery, changed payload refusal, unsafe metadata and old-history
replay. Verify denied invocations never awaken into success and do not poison
later legitimate attempts. Retain ambiguous publication state for root recovery;
never overwrite/delete/reuse its final authorization. I support the design once
the identified crash window has a tested resolution; ordinary shared/exclusive
locking alone is insufficient for a post-fsync authorization claim.
