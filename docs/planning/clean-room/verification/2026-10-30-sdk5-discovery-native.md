# SDK5 discovery native control — 2026-10-30

The first synthetic discovery attempt failed before HTTP/2; its pipe output was not retained. A separate diagnostic retained `Error: stdin unavailable` in root-owned output. Neither attempt reached its negative control; their intents and files remain retained.

The fixed PID1 stdio observation (`/tmp/sfactory-identity-admin-frney8vg`) showed that inherited FD0 was a character device with the same device number as `/dev/null` but a different filesystem device/inode. Passing `stdin=DEVNULL` gave the same device/inode as `/dev/null`. Both were opened read-write; the discovery probe's existing check requires the inode, not a read-only access mode. The production SDK's separate FD guard is unchanged.

A fresh isolated diagnostic with the same probe, explicit `stdin=DEVNULL`, root-owned bounded output capture and distinct units passed (`/tmp/sfactory-identity-admin-vya9ek1r`, `/tmp/sfactory-sdk5-discovery-diagnostic3-apply-envelope.json`). It verified HTTP/2 discovery of the four fixed synthetic services, rejection of an inherited connected FD, and fixture-unit cleanup. It did not register an SDK, contact a provider, change production, or prove production admission.
