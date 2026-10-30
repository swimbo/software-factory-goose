# Protected Linux Goose candidate — actual NUC offline verification

Continues late Phase9. This candidate has not been installed as a production worker.

Pinned upstream Goose 1.49.0 commit `71fc4be1ed729e26b1dc0a4466abdd03be548a53`,
archive SHA256 `7e90a3dc6b2bb18c8c343d36975e43ba2804b3bd3bd19d51e32ee31a01fb99b0`.
Applied 0001 SHA256 `4406ab3e759b48b2ec0615f8eff51ecace9db94d902b7895dc6eedb32db52d83`
and 0003 SHA256 `4064cd6bdc4421927bf5c48ce0decf4f5d5512a34519aa1ee839102f1255c457`;
0002 was not applied. Cargo.lock remains
`b8ae0ad19c7644ebecbaa1d66fa461f76be35f9eafbd57f5a8a17d81bfa04178`.

Actual NUC build used installed Rust1.98 with `--locked --offline -p goose-cli
--bin goose --no-default-features --features rustls-tls,disable-update,linux-protected-stdio -j2`.
The build ran in a network-none, readonly-root, cap-empty, NNP Docker container,
UID1000, bounded8GiB/256PIDs/2CPUs. Only public source/cache/toolchain/sysroot were
mounted; no Docker socket, home credentials or provider secret. A separate
uncredentialed fetch obtained pinned public dependencies before offline compilation.
The first four failed build attempts are retained; the final build container
`60070d0c922ceeb820b01bdb564ce24c0307dbd34a01e300b6eb388f2cc0ae91`
exited0 without OOM. Full logs and manifests reside under
`hermes-control:/tmp/sfactory-goose-protected-c0tz3oa4`.

Independently copied candidate `/tmp/sfactory-goose-protected-c0tz3oa4/goose-canary`
SHA256 `802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db`.
Public canary image `sha256:73097429edb51f16d6105dd67025c53e2b43c98cd8f1297a97d68b1f899348ef`
contains only the root-owned public profile and offline stub. Actual protected
UID2001 network-none readonly/NNP/cap-empty/seccomp-filtered execution completed two
stub inference requests and one structured file-tool call, then exited0. Three
separate controls (wrongUID, missingNNP, writable-root) each exited1 before any
inference or tool. Exact owned containers were removed after verified exit; their
full IDs and cleanup receipts remain in `offline-*-*.json`. `offline-results.json`
is the aggregate and `offline-positive-output.json` contains the public initial
and continuation envelopes. Fixed CWD was `/work/task`.

No Bifrost call, factory credential read, production root grant, approved promotion,
Docker/host recovery or complete factory INT-LOOP is proved by these checks.
The original inert Docker guard remained created/PID0. Existing services were not
restarted. The protected profile is an additional check, not a root-launch seal.
