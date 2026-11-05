# Gateway namespace service-peer identity

An isolated Linux socket characterization reproduces the current Root mapping shape: UID 0 and the gateway UID are mapped, while the broker has only a group mapping. Under that map, a gateway accepting the inherited bound socket sees the broker's UID as 65534. A gateway connecting to the capture socket also sees UID 65534. The broker and capture service still see the correct gateway UID, so the earlier outside-to-gateway observation did not establish mutual authentication.

| Observer | Peer | Existing-map UID | Explicit service-map UID |
|---|---|---:|---:|
| Gateway | Broker | 65534 | 2005 |
| Gateway | Capture | 65534 | 2008 |
| Broker | Gateway | 2007 | 2007 |
| Capture | Gateway | 2007 | 2007 |

These are public fixture identities. Adding their exact same-number broker and capture UID entries restores both gateway-side identities while leaving the tested GID map unchanged. The existing Bifrost ingress and owner Unix client compare the kernel UID to the configured service UID; the observations therefore imply refusal under the old map. The actual Bifrost/Root runtime was not run by this characterization, and no production mapping was changed.

The final network-disabled, read-only container exits zero, with all owned children joined. Its source, immutable image, exact command, mappings, raw observations and terminal Docker state are in [the receipt](2026-11-05-gateway-namespace-peer-identity.json). Earlier setup failures remain preserved and are not counted as product failures. Root mapping required the documented `CAP_SETFCAP` for parent UID 0; adding a filesystem override did not fix that setup problem. See the [Linux user namespace manual](https://kernel.googlesource.com/pub/scm/docs/man-pages/man-pages/+/master/man/man7/user_namespaces.7).

The launch integration must bind only the reviewed service identities in Root's writer, namespace inspection, bootstrap checks and profile fingerprints. It must retain strict peer checks and reject extra mappings or overflow-UID substitutions. Capture-group traversal, executable/descriptor custody, actual launch, wallet/capture protocol and cleanup still need their own qualification. No paid calls or shared service changes occurred.
