# Native Unix diagnostic peer canary

A fixed UID 2000, capability-empty, no-new-privileges synthetic canary passed in a private network namespace and private temporary directory on the NUC. The observer set itself non-dumpable before examining its synthetic child. The child inherited a connected Unix client FD; the observer verified bidirectional kernel Unix diagnostic peer correlation and the accepted peer's synthetic socket name. It emitted no raw socket inodes.

The reviewed source SHA-256 was `1e368e3f4e3d88cc587eb97451246defa91cc6b21625fcf871d43ce73620f0c6`. The plan envelope `/tmp/sfactory-unixdiag-peer-plan-envelope.json` points to root receipt directory `/tmp/sfactory-identity-admin-sw3fl2x1`; the apply envelope `/tmp/sfactory-unixdiag-peer-apply-envelope.json` points to `/tmp/sfactory-identity-admin-6x7lehuf`.

This establishes the tested kernel facility for one deliberately inherited synthetic connection. It does not prove access to an unrelated SDK process's FD directory, completeness of a production peer graph, absence of inherited production admin FDs, SDK admission, or production activation. Those require separate identity-bound native checks and negative controls.
