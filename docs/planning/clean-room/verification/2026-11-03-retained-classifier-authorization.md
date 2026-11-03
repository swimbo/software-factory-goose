# Retained classifier authorization prerequisite

Read-only NUC metadata confirms the factory key `software-factory-goose-int-loop-c085b7e` is active and unexpired, with `allow_all_providers=false` and only one provider association: `ollama-cloud`. Its allowed models are `auto` and the two retained answer models. There is no `vercel-classifier` association. No credential values were selected. The key has no attached team/customer, key rate limit or key/provider-config budgets in these observations; that says nothing about global/model budgets or the separate protected wallet caps.

The candidate's `runGovernedInternalCall` creates a fresh child grant with the parent's identity and evaluates the actual target provider/model before quoting, reserving or executing. `resolver.evaluateAccess` refuses a provider missing from that key's permits. Consequently the planned protected path cannot assume that loading classifier credentials into the account also authorizes this principal to use them.

## Native characterization

All runs used the unchanged installed 1,927-file source at Bifrost `de69191`, Go's race detector and public disposable fixtures. These are scope-shape characterizations, not a production policy clone or paid-provider test.

- The existing embedding test passes in 1.744s. Its helper explicitly adds classifier permission to the synthetic key.
- Replacing only that fixture's provider list with an Ollama-only policy makes the existing quote expectation fail with typed HTTP403 `policy_provider_blocked` for `vercel-classifier` (0.738s).
- Fresh child-grant checks matching the production internal-call pattern allow both answer models, deny classifier embedding/chat/Responses access, and observe zero governed embedding executor calls (2.421s).
- Adding explicit classifier permission only to the public fixture makes the existing successful embedding/accounting test pass again, including its one-executor-call assertion (1.746s). This is a control, not authorization to change the shared key.

An earlier diagnostic evaluated the fixture's original parent context, whose cached access still described its earlier provider list. The answer-model positive control caught that mismatch. The corrected fixture uses a fresh child grant, copies the parent's identity and stamps the actual provider, as `runGovernedInternalCall` does. Earlier source variants and failed logs remain preserved. No production fix resulted.

The companion JSON records timestamps, source/overlay hashes, commands and output hashes. All canonical source files still match their manifest after the runs. No shared settings, permissions or production source changed.

## Integration consequence

The bootstrap needs both scoped governance hydration and explicit, reviewed classifier authorization consistent with the protected Root principal and route inventory. It must not silently append classifier permission, set provider/model skip flags, borrow another principal or bypass governance to make startup succeed. Any concrete permission/delegation proposal belongs in the reviewed production configuration and its applicable approval gates. Existing provider-bound, custody, launch/cleanup and benchmark gates remain open; candidate disabled, benchmark 0/120.

This finding concerns the proposed protected same-parent-identity path. It does not establish that ordinary shared `auto` routing is broken.
