# Configured source qualification follow-up

The full server race suite now passes on Bifrost `e7e985e`: **62.946 seconds**, with a three-minute timeout, unchanged product/test source and explicit public qualification inputs. All 1,925 source files still match the installer-produced tree; nine staged Python modules match their recorded hashes. No paid provider or production configuration is used.

The prior nine failures were setup failures. The pricing helper already supports `BIFROST_PRICING_RENEWAL_TESTDATA`; pointing it at the existing `pricingrenewal/testdata` resolves the relative-layout mismatch. `BIFROST_WORKER_SOURCE` points to the nine-module public worker closure and `BIFROST_WORKER_PYTHON` to `/usr/bin/python3` (3.13.5). The fixture generates its own PDF, worker policy and temporary archive. Existing Poppler binaries supply document processing. No tests were skipped or rewritten to obtain this pass. Prior failed receipts remain unchanged.

## Confirmed native dependency conflict

`engine/transport/patch_native_ingress.py:51-54` deliberately installs the reviewed fasthttp body-admission derivative and adds its module replacement. Compared with the exact official v1.74.0 ZIP, the candidate changes only `http.go` and `server.go`, plus `body_admission_test.go`. The ZIP and patch hashes match the earlier native-ingress qualification. The fresh-buffer race regression passes in 1.015 seconds.

The upstream `core/providers/utils/fasthttpreplace_test.go:186-188` rejects any replacement. A compile-only control using unmodified official v1.74.0 fails because `transports/bifrost-http/server/native_ingress_profile.go:30` requires `Server.RequestBodyAdmission`, absent upstream. The control uses a separate temporary module file; the canonical source is unchanged. Removing the replacement alone cannot repair the build while preserving this interface and its pre-body/fresh-buffer protections.

Production policy remains undecided: qualify only the exact reviewed derivative under a strict integrity exception, or redesign ingress for unmodified upstream while preserving the protections. No guard was disabled, altered or counted as passing. GitHub CLI issue/PR searches returned no matching fasthttp work; the connected search could not access the repository.

## Fallback interaction to preserve

`plugins/routing/llmclassify.go::runClassifierCompletion` conditionally calls Responses after a chat error. `FactoryPhysicalAttempt.Finish` marks a noncomplete physical call refused, and the next physical admission checks that sticky state. Adding a Responses wire profile alone cannot qualify that fallback. Its reviewed rejection/billing disposition and audit closure must preserve the existing unknown-outcome fence; no free rejection or safe retry is inferred.

The companion JSON records inputs, hashes and controls. Production bootstrap/warmup/custody, provider-backed all-path bounds, NUC containment/recovery and the actual benchmark remain open. Live attempts remain 0/120; candidate disabled; existing caps and ledgers unchanged.
