# Root gateway launch composition checkpoint

The private `_launch_gateway` composes the existing bind, gated preparation and one-use release methods. It retains the direct child for the future lifecycle; a successful return proves a release acknowledgement, not gateway readiness or inference authority. A failure closes any locally owned handles, invokes the existing revoke path to fence execution and attempt wallet revocation, and requires the child to join. Failed cleanup or an unjoined child remains an explicit unknown outcome. The method is not wired to a public production entry point.

Component tests cover ordering, unknown release, cleanup failure and a child that does not join. A network-disabled Linux fixture exercised the composed method through a real unprivileged helper and synthetic target; the socket binder, grant, guard, attachment and prepared-child inspection were mocked. A separate earlier PID1 fixture covered the lower-level cgroup inspection. These results do not prove production bootstrap, real route or wallet custody, or cleanup after socket handoff. No paid inference occurred.

Supervisor SHA-256: `633bf07ac9341a5cf5bb0383bb77eb778b86745c3d6a9f6e4232637fbde68cc5`. Fixture SHA-256: `b1253ed795a95d2264df9cdab2967570c878a53a824163497ad6164e1d412ef3`.
