# Root deadline binding checkpoint

The v2 protected acquisition now relays a Root-derived deadline bounded by the current lease, prepared grant, catalog control grant, scope and route. The Go owner rejects malformed or late acknowledgements and clamps its context to that deadline and any earlier caller deadline. The v1 path is unchanged. Bifrost source commit: `e3c6bba`.

The authenticated broker must honestly relay the Root deadline. It is a snapshot, not a cryptographic Root attestation or a live revocation channel. No new spending authority is created; existing begin and admission checks remain decisive.

Verification: 33 focused Python tests passed; seven installer tests passed. On an isolated Linux source stage, the Go owner/scope tests passed with the race detector and the actual HTTP server compiled offline. The pinned installer was applied to an owned source copy after reconstructing its previous pre-exchange digest. Independent source review found no actionable defects in this narrow change. The privileged native socket test was not rerun, and these checks do not establish joined production custody, provider charge bounds or launch admission.

No paid calls or benchmark attempts were made. The candidate remains disabled.
