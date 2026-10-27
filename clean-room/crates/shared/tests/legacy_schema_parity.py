"""Bounded independent draft-07 and serde comparison, not a validation boundary."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

from jsonschema import Draft7Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
CHECK = WORKSPACE / "target/debug/examples/check_legacy_contract"
SCHEMAS = ROOT / "schemas/legacy-shape/v1"

receipt = {"status": "completed", "sha": "abc", "diff": "x", "turn_count": 3,
           "exit_code": 0, "wall_time_ms": 3, "spend_usd": 0.5}
claim = {"id": "x", "work_package_id": "w", "worker_id": "u", "git_revision": "abc",
         "lease_expiry": "2026-01-01T00:00:00Z", "status": "open"}
grant = {"id": "x", "work_package_id": "w", "scope": "example", "kind": "privileged",
         "ttl_secs": 60, "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T01:00:00Z",
         "human_approval_required": True, "approved_by": None}

class LegacyParity(unittest.TestCase):
    def test_shape_corpus(self):
        for name, valid, field, invalid in [
            ("receipt", receipt, "status", "missing"),
            ("claim", claim, "status", "missing"),
            ("credential-grant", grant, "kind", "missing"),
        ]:
            schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text())
            Draft7Validator.check_schema(schema)
            validator = Draft7Validator(schema, format_checker=FormatChecker())
            missing = copy.deepcopy(valid)
            del missing[field]
            wrong = dict(valid, **{field: invalid})
            cases = [(valid, True), (missing, False), (wrong, False)]
            if name == "receipt":
                cases.extend([
                    ({"status": "timed_out", "sha": "abc", "turn_count": 2, "wall_time_ms": 10}, True),
                    ({"status": "failed", "exit_code": 1, "stderr_tail": "error"}, True),
                    ({"status": "crashed", "signal": 9, "core_dumped": False}, True),
                    ({"status": "failed", "exit_code": "1", "stderr_tail": "error"}, False),
                ])
            for obj, expected in cases:
                with self.subTest(name=name, obj=obj):
                    self.assertEqual(validator.is_valid(obj), expected)
                    proc = subprocess.run([CHECK, name], input=json.dumps(obj), text=True,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                    self.assertEqual(proc.returncode == 0, expected)

if __name__ == "__main__":
    unittest.main()
