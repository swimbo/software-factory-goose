# Retained semantic startup storage audit

Read-only NUC metadata on November 3 confirms the retained semantic classifier still selects `embedded`, `vercel-classifier`, and `openai/text-embedding-3-small`. Its complete configuration hash matches the November 2 route audit. The database remembers dimension 1536 for that embedding identity and contains one generation-registry entry; the top-level vector-store table has no rows. The companion JSON records separate observation timestamps and sanitized hashes. No credentials, prompt values or vectors were read, and no provider, namespace or configuration-write operation ran.

In the reviewed candidate source, `plugins/routing/complexity/semanticclassifier.go::resolveStoreLocked` selects a private store for embedded mode. `embeddedStoreLocked` passes an empty `ChromemConfig`; `framework/vectorstore/chromem.go::newChromemStore` therefore uses `chromem.NewDB()`, not the persistent constructor. A fresh dedicated process preserving this configuration starts with an empty in-memory store. This is a candidate-source conclusion, not an attestation of the currently running shared binary.

`complexity/embeddingdimensions.go::adoptRememberedGeneration` treats the remembered dimension only as a lookup hint. `complexity/generations.go::adoptSemanticGeneration` requires a matching completion marker in the selected vector store. A registry claim is coordination metadata, not that marker or the vectors. Consequently the persisted dimension and claim do not establish free generation reuse across processes. The registry hash changed between observations earlier in this session; freshness, ownership and generation completeness were not inferred from it.

The adoption helper also calls `CreateNamespace` before reading the marker. It must not be invoked against shared storage as a read-only discovery probe.

## Bootstrap consequence

Continue with an owned, captured and pre-dispatch-bounded semantic warmup, or separately qualify a complete generation transfer/adoption mechanism. Preserve the retained model, route and storage contract; do not silently switch to configured storage or assume the shared process's RAM is reusable. Warmup must participate in the existing spending authority and caps before hosted calls can be admitted. This audit does not establish that every possible transfer mechanism requires paid warmup.

Production bootstrap, provider bounds and NUC lifecycle qualification remain open. Candidate disabled; benchmark 0/120.
