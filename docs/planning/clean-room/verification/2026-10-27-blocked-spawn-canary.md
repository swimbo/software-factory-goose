# Blocked launch and brake canary

`cargo run -p watchdog --example blocked_spawn_probe --locked --offline` passed as a **negative control** on the local macOS host. An owned child's setup announced readiness and blocked on an inherited socket while `Registry::spawn_in_family` held the registry mutex. A concurrent stop did not return within 300 ms. Releasing child setup allowed spawn to return and the stop to kill and reap the owned group. The fixture uses no caller-supplied PID, existing service, account or credential; closing the parent socket also releases child setup on process failure.

This demonstrates that the existing broker cannot prove an independent, bounded emergency brake during blocked launch. A passing canary records the limitation; it is not a passing operational stop gate. It does not establish behavior after supervisor SIGKILL or containment of escaped descendants. The fixture preserves direct child ownership and does not signal a PID after reaping.
