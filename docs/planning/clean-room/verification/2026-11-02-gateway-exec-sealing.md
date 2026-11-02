# Gateway helper source sealing

Root supervisor source SHA-256 `6ab2ac63347718c3d7c640d5ce86bbcfb25799461beb6aea10aebb9c3932d427` adds `stage_gateway_exec`, which reads the protected helper with its fixed SHA-256 `0f25e4b3206115469b188594250a837eb7ad1194d9715372b4f69d1bb65d34b5`, verifies its bytes, and seals them in a close-on-exec Linux memfd. A future launcher must explicitly pass the descriptor to Python. The function is not connected to a launch entry point.

Two focused tests passed in an isolated, network-disabled Linux container. They reject changed bytes, verify the descriptor's seals and close-on-exec flag, reject modification and truncation, and execute the helper through `/proc/self/fd` with a deliberately invalid request. The tests substitute the protected-file reader and do not prove source installation, Root process launch, cgroup attachment, production custody, or provider admission. No paid calls occurred.
