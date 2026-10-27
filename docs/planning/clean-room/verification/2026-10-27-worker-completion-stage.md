# Worker completion response consistency

The private worker adapter validates that a returned claim's completion stage agrees with
the exact receipt and attempt. A success must be Evaluating; a failure must be CoolingDown
or Failed. The latter is allowed because retry exhaustion or cooldown arithmetic overflow
can fail a task. A contradictory backend completion is reported as 502 with outcome unknown;
an inconsistent stored completion is refused before another completion call. This check is
defensive and does not replace the claim journal's atomic proof and expiry enforcement.

An actual private Unix-socket test with a deliberately inconsistent backend returned 200
before the fix. After the fix it returns 502, then 409 on retry without a second backend call.
Existing exact-retry behavior passes with a backend that returns the correct failure stage.
The all-feature control-plane library run passed these adapter and claim tests, but its wider
run had three unrelated gateway fixture failures; it is not a passing full-suite receipt.
This same-UID mock test does not prove production identity or containment.
