# Generic Phase 11A image; source, Goose and relay are mounted read-only by Root.
FROM sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937
WORKDIR /factory
ENTRYPOINT ["/usr/local/bin/python3", "-I", "-B", "/factory/linux_worker.py"]
