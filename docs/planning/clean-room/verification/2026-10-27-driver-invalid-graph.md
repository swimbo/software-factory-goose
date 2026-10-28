# Diagnostic driver invalid graph refusal

The in-memory driver silently overwrote duplicate task IDs while building its dependency index and could still dispatch an unrelated ready task when another part of the graph had a cycle or missing dependency. A regression test failed before the change. The driver now rejects duplicate IDs and validates the complete graph before returning dispatchable tasks or mutating completion; invalid graphs return no work and remain unchanged. The focused driver tests pass.

This is a diagnostic graph safeguard. It does not create durable task authority, authenticate the task DAG, bind it to intake or receipts, or authorize production scheduling.
