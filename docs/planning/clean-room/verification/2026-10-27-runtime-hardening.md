# Runtime hardening evidence

The diagnostic pipeline now refuses automatic dispatch in the human lane, passing evaluation before the same task has a completed build, and duplicate completed-build admission. These remain in-memory diagnostics, not durable claim or evaluator authority.

The gateway rejects malformed credential-bearing base URLs and reservation authorities before issuing requests. It permits HTTPS or literal loopback HTTP and rejects userinfo, query strings and fragments; synthetic tests reproduced requests to malformed endpoints before the fix. This does not establish peer identity or a trusted production gateway.

The partial shell filter now refuses ambiguous executable syntax and additional shell metacharacter cases. A quoted executable bypass was reproduced before the fix. The safe `>&2` redirection used by the existing masking test initially regressed and was corrected; the full execution tests subsequently passed. This filter is not a complete shell parser or an OS containment boundary.

The claim projection's evaluating state now requires a completed receipt from its current attempt and a full candidate revision, with no active lease. A disposable Restate/PostgreSQL fixture also tested a failed first attempt followed by a successful second attempt and re-export. This validates internal consistency, not candidate Git provenance or authoritative evaluation.
