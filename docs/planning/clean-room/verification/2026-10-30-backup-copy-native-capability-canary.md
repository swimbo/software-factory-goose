# Native backup copy capability canary

The fixed public-data canary passed on the NUC through the root bridge. Its plan envelope was `/tmp/sfactory-backup-copy-canary-plan-envelope.json`, with root receipt directory `/tmp/sfactory-identity-admin-m4h0onxm`. The apply envelope was `/tmp/sfactory-backup-copy-canary-apply-envelope.json`, with root receipt directory `/tmp/sfactory-identity-admin-8hmqa16t`.

The reviewed plan bound copy-source SHA-256 `7748f506082b8ea23dd869923200f6d2868ce81e8ec151f02340017fb66d3f4e` and bridge effective capabilities `0000000000040003`: CHOWN, DAC_OVERRIDE and SYS_CHROOT, without FOWNER. The returned apply result reports equal synthetic source, backup and restore bytes and matching UID 2004 metadata. Its fixture and intent are retained under the fixed public-only scope; the result records `production_data: false`.

This is evidence for the pinned copy primitive under the tested bridge capabilities. It is not a production backup, Restate restart, journal-history comparison, full restore proof, SDK admission or cutover approval. The production coordinator and restore candidates require separate review and gates.
