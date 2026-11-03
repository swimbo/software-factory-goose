# Reviewed Responses charge contract

This checkpoint adds source-only arithmetic/schema support for the retained classifier's conditional Responses path. It is not provider attestation, production construction or live admission.

## Charge model and compatibility

`ReviewedResponsesContract` is distinct from the chat-only `ReviewedModelContract` and embedding schema. It requires `api=responses`, `output_limit_field=max_output_tokens`, bounded input/output (including reasoning), positive reviewed rates, fixed fees, a request-byte limit, a bounded model identifier, canonical review digest and validity. Each token component is rounded upward separately in integer microUSD before fixed fees and physical-attempt multiplication. Responses components participate in the same independently supplied complete inventory, aggregate 32-attempt capacity, $0.75 logical/permanent-task ceilings and six-attempt permanent reservation calculation. No refund or retry rule changes.

An empty Responses inventory is omitted from serialized reviews. Frozen pre-existing chat and embedding review bindings remain `b030c01140f22738d889ecc4fe19a6991ed6084a2aac7a684689aa0c6d324b78` and `b9b5ef4726b2e41c9ea81cd393d38a1c80011b37da40e00c1e13aaeb9adee1e0` respectively. Tests verify exact bytes as well as hashes. Fictional provider inputs establish arithmetic/schema behavior only.

The new mixed-route test failed before implementation with `unknown field responses_components` (exit101), then all 15 charge-bound tests passed. Additional tests cover endpoint/schema separation, missing/unknown fields, invalid or overflowing bounds, interval coverage, cross-API duplicate IDs, total attempts, hash changes and permanent-task affordability.

Full control-plane library validation with `--features restate` passed **293 tests**, with the existing owned-Restate/private-relay test ignored. Strict Clippy (`--lib --tests -- -D warnings`), scoped rustfmt and diff checks passed.

Seven-lens source review completed with no primary findings, and the simplification pass needed no edits. The Claude peer failed before source egress; review used the required in-process adversarial fallback. Review found two coverage gaps, now closed in the existing tests: sub-microUSD input/output each reserve one microUSD separately, and invalid review evidence is rejected through the complete route reservation entry point. A combined-rounding mutant and a skipped-Responses-validation mutant both failed at the intended runtime assertions. The exact implementation was restored afterward; source hashes and mutation outputs are recorded in the JSON. The library/Clippy results above were repeated on the final strengthened tests before publication.

## Actual converter characterization

An offline Go race test on `hermes-control` used the pinned Bifrost `e7e985e` schema conversion (`BifrostChatRequest.ToResponsesRequest`) and actual OpenAI request converter/marshaller. The synthetic system/user classifier input retained `openai/gpt-6-luna` and its 512-token cap as `max_output_tokens`; removing temperature followed `runClassifierCompletion`. The resulting body omitted `store`, `background`, tools, previous-response state and service tier. Omission is not evidence of upstream defaults or custody. This test does not exercise the final transport, `pinproxy` or a provider.

The focused package race test passed in 1.141s. A Go overlay supplied the public test without changing canonical source: all 1,925 installed source files matched their original hashes afterward. The companion JSON records the source identity, complete public overlay source/hash and observed synthetic body. The disposable probe remains `/home/bo/sfactory-gateway-wire-20261102/responses-characterization_test.go`; it contains no credentials or real prompt content.

## Remaining production work

The Rust contract must be matched to a reviewed Go final-wire Responses predicate and to independent supported provider/proxy evidence. The retained classifier sends Responses only after selected chat errors. Existing physical capture refuses subsequent dispatch after a noncomplete call: a new API profile cannot by itself make that fallback admissible. Qualify rejection/billing disposition and audit closure without treating an error as free or retrying an unknown outcome. Responses completion/status and usage handling also need qualification.

The fasthttp policy conflict is unchanged. Production bootstrap, owned semantic warmup, route/credential/plugin custody, NUC launch/recovery and the benchmark remain open. Candidate disabled; live attempts 0/120; no provider calls or deployment in this checkpoint.
