"""Independent black-box public-task acceptance; never load candidate Python here.

Only contract() is generator-visible. cases(), expected values and receipts stay
in the evaluator controller. The trusted executor contains solution.py separately,
receives inputs/initial fixtures only, and collects filesystem evidence itself.
This suite does not expose or replace the factory's protected holdouts.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re


MAX_OUTPUT = 65536
DIGEST = re.compile(r"[0-9a-f]{64}\Z")

INTERFACES = {
    "csv-totals": 'Input {"csv":text} includes header item,quantity,price. Return an object of item to exact decimal total strings, sorted by item. Header-only input returns {}. Malformed headers/rows/numbers are invalid; no partial result.',
    "json-lines": 'Input {"field":name,"input":JSONLinesText}. Return sorted counts keyed by field value: strings remain literal; other JSON values use compact sorted-key JSON as their key. Invalid JSON/missing fields are invalid. Empty input returns {}.',
    "intervals": 'Input {"intervals":[[start,end],...]}. Return merge_intervals output as a sorted list of closed integer interval pairs; merge touching endpoints, not merely adjacent integers. Reversed endpoints are invalid.',
    "topological-order": 'Input {"graph":{node:[outgoingNeighbor,...],...}}. Return lexicographically smallest topological node list, including nodes appearing only as neighbors. A cycle is invalid with no partial result.',
    "lru-cache": 'Input {"capacity":nonnegativeInteger,"ops":[["put",key,value],["get",key],...]}. Return the list of get results only, using null for a miss. Every get refreshes recency, overwrite refreshes recency, zero capacity stores nothing. Invalid capacity is invalid.',
    "event-dedup": 'Input {"input":JSONLinesText}. Return a list of original event objects, preserving the first occurrence of each string id. Missing/non-string id or malformed JSON is invalid; empty input returns [].',
    "markdown-toc": 'Input {"markdown":text}. Return TOC text with one line "- [Heading](#anchor)" per ATX heading, two leading spaces per heading level beyond one, and a final newline when nonempty. Ignore headings inside backtick/tilde fences. Anchors are lowercase text, punctuation removed, whitespace to hyphens, duplicates suffix -1,-2. Empty TOC is "".',
    "query-encoding": 'Encode input {"pairs":[[key,value],...]} as a query string using UTF-8 percent escaping and plus for spaces. Decode input {"query":text} as ordered [key,value] pairs, preserving repeated keys and blank values. Exactly one of pairs/query is supplied.',
    "retry-schedule": 'Input {"base":nonnegativeInteger,"attempts":nonnegativeInteger,"max_delay":nonnegativeInteger}. Return [min(base*2**i,max_delay) for i from zero up to attempts-1]. Booleans/fractions/negative inputs are invalid. No sleeping or network.',
    "duration-format": 'Input is either {"duration":text} or {"seconds":nonnegativeInteger}. Parse concatenated, unique d/h/m/s integer units in descending order; reject whitespace, duplicate units, fractions and negatives. Return {"seconds":integer,"formatted":canonicalText}, omitting zero units, with zero formatted as "0s".',
    "ini-roundtrip": 'Input {"ini":text}. Return section-to-key/value objects with sorted section/key names, preserving key case and literal string values (including %). Duplicate sections/keys and invalid INI are invalid. Empty input returns {}.',
    "dependency-impact": 'Input {"dependencies":{node:[dependency,...]},"changed":node}. Return the sorted transitive reverse dependents, excluding the changed node itself and suppressing duplicates even in cycles.',
    "text-index": 'Input {"text":text,"word":query}. Return sorted distinct one-based line numbers for the exact lowercased word. Words are runs of Unicode letters (no digits/underscore); punctuation separates words. Query is lowercased, never a substring match.',
    "semver-sort": 'Input {"versions":[version,...]}. Return stable SemVer 2.0 precedence order. Preserve original build metadata; versions differing only by build metadata retain input order. Invalid versions/leading zero numeric identifiers are invalid.',
    "atomic-config": 'Input {"path":relativePath,"replacement":object}. The existing JSON config at path is replaced atomically through a same-directory temporary file only if replacement has string keys and nonnegative integer values (booleans invalid). Return the resulting object. Invalid replacement returns invalid and leaves the original file untouched. Paths remain inside the approved scratch directory.',
    "bounded-queue": 'Input {"capacity":nonnegativeInteger,"ops":[["put",value],["get"],...]}. Return one response per op: put yields {"status":"stored"} or {"status":"full"}; get yields {"status":"value","value":value} or {"status":"empty"}. Capacity zero is always full/empty. Invalid capacity is invalid.',
    "matrix-transform": 'Input {"op":"transpose"|"rotate","matrix":[[value,...],...]}. Return rectangular transpose or clockwise rotation. [] returns []; ragged matrices are invalid.',
    "log-summary": 'Input {"input":JSONLinesText}. Records have severity in DEBUG,INFO,WARNING,ERROR,CRITICAL and a string message. Return sorted severity objects {"count":integer,"max_length":integer}; lengths count Unicode characters. Unknown severities/malformed records are invalid. Empty input returns {}.',
    "invoice-rounding": 'Input {"lines":[{"quantity":nonnegativeInteger,"price":decimalString},...],"discount":decimalRateString,"tax":decimalRateString}. Return strings subtotal,discount,tax,total, all two decimals. Round the sum of raw line totals half-up to cents, then rounded subtotal*discount, then (subtotal-discount)*tax, then total. Rates are from zero through one; floats and negative quantities/prices are invalid.',
    "file-manifest": 'Input {"directory":relativePath}. Return a sorted object mapping slash-separated relative regular-file paths to lowercase SHA256 hex. Recurse directories, never follow symlinks to files/directories; empty directory returns {}. Missing/non-directory input is invalid. Paths remain inside approved scratch.',
}


@dataclass(frozen=True)
class Case:
    request: dict
    expected: dict


def _case(request, result=None, *, invalid=False):
    return Case(request, {"error": "invalid"} if invalid else {"result": result})


def task_ids():
    return tuple(sorted(INTERFACES))


def contract(task_id):
    return (
        "Public benchmark interoperability contract (identical for both harnesses): "
        "deliver solution.py, README.md and test_solution.py using only the standard library. "
        "Keep the requested library API where applicable and add an executable JSON Lines wrapper: "
        "python3 -I -B solution.py reads one JSON request per stdin line and emits exactly one "
        'JSON object line, either {"result":value} or {"error":"invalid"}. '
        "Do not emit commentary to stdout. Document an executable test command in README.md. "
        + INTERFACES[task_id]
    )


def fixtures(task_id):
    setup = {"files": {}, "directories": ("scratch",), "symlinks": {}, "pin_files": ()}
    if task_id == "atomic-config":
        setup["files"] = {f"scratch/config-{i}.json": b'{"x":1}' for i in range(3)}
        setup["pin_files"] = tuple(setup["files"])
    elif task_id == "file-manifest":
        setup["files"] = {
            "scratch/tree/a.txt": b"hello\n",
            "scratch/tree/nested/b.bin": bytes((0, 255, 1)),
            "scratch/sentinel.bin": b"must not appear in tree manifest",
        }
        setup["directories"] = (
            "scratch",
            "scratch/tree",
            "scratch/tree/nested",
            "scratch/tree/empty",
            "scratch/empty",
        )
        setup["symlinks"] = {"scratch/tree/link": "../sentinel.bin"}
    elif task_id not in INTERFACES:
        raise ValueError("unknown task")
    return setup


def cases(task_id):
    all_cases = {
        "csv-totals": (
            _case(
                {
                    "csv": "item,quantity,price\npear,2,0.10\napple,3,1.25\npear,1,0.20\n"
                },
                {"apple": "3.75", "pear": "0.40"},
            ),
            _case({"csv": "item,quantity,price\n"}, {}),
            _case(
                {"csv": "item,quantity,price\npear,2,1.00\nbad,nope,1.00\n"},
                invalid=True,
            ),
        ),
        "json-lines": (
            _case(
                {
                    "field": "kind",
                    "input": '{"kind":"z"}\n{"kind":"a"}\n{"kind":"z"}\n',
                },
                {"a": 1, "z": 2},
            ),
            _case({"field": "kind", "input": ""}, {}),
            _case({"field": "kind", "input": '{"kind":"a"}\n{}\n'}, invalid=True),
            _case({"field": "kind", "input": '{"kind":"a"}\nnot-json\n'}, invalid=True),
        ),
        "intervals": (
            _case({"intervals": [[8, 9], [3, 5], [1, 3]]}, [[1, 5], [8, 9]]),
            _case({"intervals": []}, []),
            _case({"intervals": [[5, 2]]}, invalid=True),
        ),
        "topological-order": (
            _case({"graph": {"a": ["c"], "b": ["c"], "c": []}}, ["a", "b", "c"]),
            _case({"graph": {}}, []),
            _case({"graph": {"a": ["b"], "b": ["a"]}}, invalid=True),
            _case({"graph": {"b": ["c"], "a": []}}, ["a", "b", "c"]),
        ),
        "lru-cache": (
            _case(
                {
                    "capacity": 2,
                    "ops": [
                        ["put", "a", 1],
                        ["put", "b", 2],
                        ["get", "a"],
                        ["put", "c", 3],
                        ["get", "b"],
                        ["get", "c"],
                    ],
                },
                [1, None, 3],
            ),
            _case({"capacity": 0, "ops": [["put", "a", 1], ["get", "a"]]}, [None]),
            _case(
                {
                    "capacity": 1,
                    "ops": [["put", "a", 1], ["put", "a", 2], ["get", "a"]],
                },
                [2],
            ),
            _case({"capacity": -1, "ops": []}, invalid=True),
        ),
        "event-dedup": (
            _case(
                {"input": '{"id":"b","v":1}\n{"id":"a","v":2}\n{"id":"b","v":3}\n'},
                [{"id": "b", "v": 1}, {"id": "a", "v": 2}],
            ),
            _case({"input": ""}, []),
            _case({"input": '{"id":"a"}\n{"id":2}\n'}, invalid=True),
        ),
        "markdown-toc": (
            _case(
                {"markdown": "# Intro\n```python\n# hidden\n```\n## Detail\n# Intro\n"},
                "- [Intro](#intro)\n  - [Detail](#detail)\n- [Intro](#intro-1)\n",
            ),
            _case({"markdown": "plain text\n"}, ""),
            _case(
                {"markdown": "~~~\n## hidden\n~~~\n### Deep!\n"},
                "    - [Deep!](#deep)\n",
            ),
        ),
        "query-encoding": (
            _case(
                {"pairs": [["name", "café"], ["name", ""], ["q", "a b%"]]},
                "name=caf%C3%A9&name=&q=a+b%25",
            ),
            _case(
                {"query": "a=1&a=&b=x+y&u=%C3%A9"},
                [["a", "1"], ["a", ""], ["b", "x y"], ["u", "é"]],
            ),
            _case({"pairs": []}, ""),
        ),
        "retry-schedule": (
            _case({"base": 2, "attempts": 5, "max_delay": 7}, [2, 4, 7, 7, 7]),
            _case({"base": 0, "attempts": 0, "max_delay": 0}, []),
            _case({"base": True, "attempts": 2, "max_delay": 7}, invalid=True),
            _case({"base": -1, "attempts": 2, "max_delay": 7}, invalid=True),
        ),
        "duration-format": (
            _case({"duration": "1h30m"}, {"seconds": 5400, "formatted": "1h30m"}),
            _case({"seconds": 90061}, {"seconds": 90061, "formatted": "1d1h1m1s"}),
            _case({"seconds": 0}, {"seconds": 0, "formatted": "0s"}),
            _case({"duration": "1h1h"}, invalid=True),
            _case({"duration": "1.5s"}, invalid=True),
            _case({"seconds": -1}, invalid=True),
        ),
        "ini-roundtrip": (
            _case(
                {"ini": "[z]\nMixed = 100%\n[a]\nx=hello\n"},
                {"a": {"x": "hello"}, "z": {"Mixed": "100%"}},
            ),
            _case({"ini": ""}, {}),
            _case({"ini": "[a]\nx=1\nx=2\n"}, invalid=True),
        ),
        "dependency-impact": (
            _case(
                {
                    "dependencies": {"a": [], "b": ["a"], "c": ["b"], "d": ["a"]},
                    "changed": "a",
                },
                ["b", "c", "d"],
            ),
            _case(
                {"dependencies": {"a": ["b"], "b": ["a"], "c": ["b"]}, "changed": "a"},
                ["b", "c"],
            ),
            _case({"dependencies": {"a": []}, "changed": "missing"}, []),
        ),
        "text-index": (
            _case(
                {"text": "Alpha alpha, café.\nBETA alpha\ncafé\n", "word": "alpha"},
                [1, 2],
            ),
            _case(
                {"text": "Alpha alpha, café.\nBETA alpha\ncafé\n", "word": "CAFÉ"},
                [1, 3],
            ),
            _case({"text": "alphabet\n\n", "word": "alpha"}, []),
        ),
        "semver-sort": (
            _case(
                {"versions": ["1.0.0", "1.0.0-rc.10", "1.0.0-rc.2", "1.0.0-alpha"]},
                ["1.0.0-alpha", "1.0.0-rc.2", "1.0.0-rc.10", "1.0.0"],
            ),
            _case({"versions": ["1.0.0+z", "1.0.0+a"]}, ["1.0.0+z", "1.0.0+a"]),
            _case({"versions": ["1.0.0-01"]}, invalid=True),
            _case({"versions": ["01.0.0"]}, invalid=True),
        ),
        "atomic-config": (
            _case({"path": "scratch/config-0.json", "replacement": {"x": 2}}, {"x": 2}),
            _case(
                {"path": "scratch/config-1.json", "replacement": {"x": -1}},
                invalid=True,
            ),
            _case(
                {"path": "scratch/config-2.json", "replacement": {"x": True}},
                invalid=True,
            ),
        ),
        "bounded-queue": (
            _case(
                {
                    "capacity": 2,
                    "ops": [
                        ["put", 1],
                        ["put", 2],
                        ["put", 3],
                        ["get"],
                        ["get"],
                        ["get"],
                    ],
                },
                [
                    {"status": "stored"},
                    {"status": "stored"},
                    {"status": "full"},
                    {"status": "value", "value": 1},
                    {"status": "value", "value": 2},
                    {"status": "empty"},
                ],
            ),
            _case(
                {"capacity": 0, "ops": [["put", 1], ["get"]]},
                [{"status": "full"}, {"status": "empty"}],
            ),
            _case({"capacity": -1, "ops": []}, invalid=True),
        ),
        "matrix-transform": (
            _case(
                {"op": "transpose", "matrix": [[1, 2, 3], [4, 5, 6]]},
                [[1, 4], [2, 5], [3, 6]],
            ),
            _case(
                {"op": "rotate", "matrix": [[1, 2, 3], [4, 5, 6]]},
                [[4, 1], [5, 2], [6, 3]],
            ),
            _case({"op": "rotate", "matrix": []}, []),
            _case({"op": "transpose", "matrix": [[1], [2, 3]]}, invalid=True),
        ),
        "log-summary": (
            _case(
                {
                    "input": '{"severity":"INFO","message":"éé"}\n{"severity":"ERROR","message":"bad"}\n{"severity":"INFO","message":"x"}\n'
                },
                {
                    "ERROR": {"count": 1, "max_length": 3},
                    "INFO": {"count": 2, "max_length": 2},
                },
            ),
            _case({"input": ""}, {}),
            _case({"input": '{"severity":"TRACE","message":"x"}\n'}, invalid=True),
        ),
        "invoice-rounding": (
            _case(
                {
                    "lines": [{"quantity": 3, "price": "0.335"}],
                    "discount": "0.10",
                    "tax": "0.20",
                },
                {
                    "subtotal": "1.01",
                    "discount": "0.10",
                    "tax": "0.18",
                    "total": "1.09",
                },
            ),
            _case(
                {
                    "lines": [{"quantity": 1, "price": "0.005"}],
                    "discount": "0",
                    "tax": "0",
                },
                {
                    "subtotal": "0.01",
                    "discount": "0.00",
                    "tax": "0.00",
                    "total": "0.01",
                },
            ),
            _case(
                {
                    "lines": [{"quantity": -1, "price": "1.00"}],
                    "discount": "0",
                    "tax": "0",
                },
                invalid=True,
            ),
            _case(
                {"lines": [{"quantity": 1, "price": 1.1}], "discount": "0", "tax": "0"},
                invalid=True,
            ),
        ),
        "file-manifest": (
            _case(
                {"directory": "scratch/tree"},
                {
                    "a.txt": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
                    "nested/b.bin": "47ffa3ea45a70b8a41c2c0825df323c00a8b7a01c1ea06083cc41dddcc001123",
                },
            ),
            _case({"directory": "scratch/empty"}, {}),
            _case({"directory": "scratch/missing"}, invalid=True),
        ),
    }
    return all_cases[task_id]


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _json(raw):
    return json.loads(
        raw,
        object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
    )


def _files_match(task_id, setup, evidence):
    files = evidence.get("files")
    pinned = evidence.get("original_fd_bytes")
    links = evidence.get("symlinks")
    if (
        type(files) is not dict
        or type(pinned) is not dict
        or links != setup["symlinks"]
    ):
        return False
    expected_files = dict(setup["files"])
    if task_id == "atomic-config":
        expected_files["scratch/config-0.json"] = b'{"x":2}'
        if pinned != setup["files"] or set(files) != set(expected_files):
            return False
        return all(
            type(value) is bytes
            and _canonical(_json(value)) == _canonical(_json(expected_files[name]))
            for name, value in files.items()
        )
    return files == expected_files and pinned == {}


def evaluate(task_id, artifact_sha256, executor):
    """Executor is a trusted contained black-box runner, never a candidate callback.

    It receives only JSON inputs and initial filesystem fixtures. Exit status alone
    cannot establish acceptance. Root-owned post-files and pinned original file
    descriptions verify real config preservation/replacement and manifest behavior.
    Pinned file descriptions detect in-place writes; they do not by themselves
    constitute a syscall proof of the precise temporary-file implementation.
    """
    if (
        task_id not in INTERFACES
        or not isinstance(artifact_sha256, str)
        or not DIGEST.fullmatch(artifact_sha256)
    ):
        raise ValueError("invalid evaluator binding")
    selected = cases(task_id)
    expected = tuple(_canonical(c.expected) for c in selected)
    # Snapshot expected values BEFORE executor invocation; it never receives them.
    inputs = tuple(json.loads(_canonical(c.request)) for c in selected)
    setup = fixtures(task_id)
    setup_snapshot = fixtures(task_id)
    accepted = safety = False
    try:
        evidence = executor(inputs, setup)
        safety = (
            type(evidence) is dict
            and evidence.get("sandbox_verified") is True
            and evidence.get("cleanup_verified") is True
        )
        stdout = evidence.get("stdout") if type(evidence) is dict else None
        stderr = evidence.get("stderr") if type(evidence) is dict else None
        if (
            safety
            and type(stdout) is bytes
            and len(stdout) <= MAX_OUTPUT
            and type(stderr) is bytes
            and len(stderr) <= MAX_OUTPUT
            and type(evidence.get("exit_code")) is int
            and evidence["exit_code"] == 0
            and evidence.get("timed_out") is False
            and evidence.get("overflow") is False
        ):
            lines = stdout.decode("utf-8", "strict").splitlines()
            observed = tuple(_canonical(_json(line)) for line in lines)
            accepted = observed == expected and _files_match(
                task_id, setup_snapshot, evidence
            )
    except Exception:
        accepted = False
    result = {
        "artifact_sha256": artifact_sha256,
        "accepted": accepted,
        "independent": True,
        "safety_passed": safety,
        "evaluator_build": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    result["evaluation_receipt_sha256"] = hashlib.sha256(
        _canonical({"task_id": task_id, "case_count": len(selected), **result}).encode()
    ).hexdigest()
    return result
