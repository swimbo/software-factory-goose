# Writer quarantine and generation-bound freeze

The snapshot gate now requires the generation's sealed writer kind and candidate path/device/inode/mode binding, verified exact-root teardown and fixed slice emptiness, private matching task/run records, durable `done` and the exact fixed writer-success digest. It reconstructs canonical file arguments from frozen bytes and compares their digest with the provider-bound fence. It requires exactly baseline README plus two regular single-link bounded outputs, rejects extras/changed baseline, and preserves bytes including CRLF.

## Actual NUC positive

`nuc_writer_freeze_spike.py` ran a known synthetic payload through the real fixed contained writer and Batch lifecycle, recorded synthetic inference/tool transitions with the actual writer result, stopped roots and passed the revised freeze. Its systemd ExecStopPost cleanup receipt and same-slice empty check passed; the original inert name reservation was checked before and after. Retained `/tmp/sfactory-freeze-positive-x6qb2zu6/task`; raw `2026-10-28-nuc-writer-freeze-positive.log`.

This positive proves creation-to-snapshot binding for known synthetic `print(1)`/`pass` files. It does not claim those files implement the task, pass behavior holdouts, came from Bifrost, or complete INT-LOOP.

## Local discriminating controls

`test_nuc_writer_quarantine.py` and `test_nuc_int_loop_evaluator.py`: seven test methods passed, with subcases. Actual infrastructure child processes exit before effects, after the first link, and after complete writes with lost acknowledgement. The original durable fence remains unknown, reissue is denied and snapshot/result publication is withheld, even when both files look complete. Injected unlink/directory-sync failures refuse success; unresolved root cleanup blocks snapshot even with a completed inference fence. Exact-entry, baseline, hardlink, substituted-generation, modified-provider-byte and complete-looking-unknown controls reject; accepted snapshot hashes and mode are checked positively.

Candidate code is never launched on the host. The tests execute the known infrastructure writer only; real candidate behavior is checked through separate read-only owned containers. This is scoped fixture evidence, not production identity, authority migration, host/daemon recovery or acceptance.
