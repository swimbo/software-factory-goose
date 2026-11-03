# Responses wire and completion qualification

[Bifrost e4331a3](https://github.com/swimbo/bifrost-local/commit/e4331a36f661a0656fe6440e0babb47c6b73b79f) is pushed and its remote SHA verified. This source-only checkpoint adds the retained classifier's synchronous text Responses profile and a separate physical completion format. It does not qualify production bootstrap, provider guarantees or live fallback admission.

## What the source enforces

The reviewed component must select `/responses`, the classifier role, `max_output_tokens` and its positive reviewed maximum. The common authorizer still binds the exact model, canonical URI, final body hash/byte limit, noncredential headers, independent policy digest, v2 owner scope and immutable acquisition-time component/call limits. The Responses profile accepts bounded text input only, requires explicit `store:false`, and refuses provider tools, remote media/history references, background execution, streaming, competing output fields and unknown request fields.

`responses_json` requires HTTP200, canonical `object:response` and `status:completed`, a hashed response ID, both input/output usage counts, and no error, incomplete-details or contradictory storage/background controls. Existing duplicate-key validation and explicit canonical control/usage casing prevent decoder aliases from converting an incomplete call into a complete one. Known usage and hashes from nonterminal responses remain observed with an unknown disposition; the registry refuses every subsequent physical permit. A chat HTTP400 followed by a Responses URI is also refused without another authorization. No refund or retry rule changed.

## Evidence and boundaries

Tests failed before implementation because both the new format and review profile were unsupported. A further counterexample exposed HTTP202 false completion; another exposed conflicting status/usage casing. The fixes reject those cases. Actual Bifrost schema/OpenAI conversion is exercised with the frozen `openai/gpt-6-luna` classifier model and a 512-token cap. An actual loopback fasthttp transport test captures completed/incomplete Responses, retains sanitized usage and blocks a second dispatch after incomplete output.

Nine network-disabled, read-only-container native fixtures passed with distinct broker/capture/gateway UIDs: completed Responses capture, incomplete Responses refusal/poisoning, the prior v1/v2 successes, changed owner call-limit refusal, and four deadline/close/router regressions. These exercise real owner-library/Unix-peer paths with synthetic broker authority, route, model responses and charge inputs. They are not a real production Root launcher, wallet/route join or lifetime custody proof. Exact containers were checked absent. The first disposable setup failed before test execution because its public staging directory was mode0700; the failed receipt/rootfs was retained, and fresh cases ran after setting only that public fixture root to0755.

Five overlay mutants failed at the intended runtime assertions: missing terminal check, missing output cap, missing explicit storage control, missing usage-case check and missing control-case check. Overlays left canonical installed source unchanged. The simplification pass removed only a redundant two-line comment; proof tests are unchanged. The final artifact was repinned and reconstructed from the exact prior 1,925-file source. Altered artifacts and installer replay were refused before changing targets; the exact core archive installer independently reproduces all four changed core artifacts. Ten installer tests, Ruff and scoped formatting pass.

On the final repinned source, the full schema race suite passed in 14.332s, the configured full server race suite in 62.212s, and selected factory utility race tests in 3.061s. All nine native cases were repeated against the final race binary (`15356457c5684d48f84334f9868d1d326fe34a3b39425ac47fb61888472c9cbe`); containers are absent and all 1,925 source hashes remain unchanged. A focused final guard rerun reproduces the unchanged fasthttp replacement-policy failure (0.093s); the selected utility pass does not satisfy full utility qualification.

Seven-lens source review completed without actionable findings or test gaps. The Claude route failed before content egress, and the required local adversarial fallback completed. A late Unicode-folding candidate was tested against the actual pinned Bifrost decoder: status and token counts agreed with capture in three cases (1.482s race pass), so no speculative guard was added. This is evidence for that decoder/build, not untested architectures or all possible Unicode inputs.

The companion JSON records source identities, test/fixture receipts, mutations and final qualification. Discarded/superseded stages and failed setup evidence remain preserved; no production service or credential configuration changed.

## Still required before live use

The current retained classifier omits `store`; a dedicated protected bootstrap must supply explicit false before this profile can admit it. The test proves that omission is refused, not that production storage custody is established. Do not silently change shared settings, the retained models or fallback semantics.

A chat rejection does not become free or safely retryable. Reviewed rejection/billing disposition and audit closure are still required before its conditional Responses fallback can operate. Supported all-path provider/proxy bounds, correspondence to the Rust charge review, owned semantic warmup, credential/plugin/log-sink custody, joined NUC containment/cleanup/recovery and the fasthttp policy decision remain open. Benchmark 0/120; no paid inference, deployment, activation or promotion occurred.
