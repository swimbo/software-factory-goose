#!/usr/bin/env python3
"""Build only: verified QuickJS source directory + private output path; no install/download."""

import argparse
import hashlib
from pathlib import Path
import subprocess

# Source archive: https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz
ARCHIVE_SHA256 = "b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if hashlib.sha256(args.archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        p.error("QuickJS archive digest mismatch")
    import tarfile

    with tarfile.open(args.archive) as archive:
        for member in archive.getmembers():
            if member.isfile():
                relative = Path(member.name).relative_to("quickjs-2026-06-04")
                if (
                    args.source.joinpath(relative).read_bytes()
                    != archive.extractfile(member).read()
                ):
                    p.error("QuickJS source mismatch")
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sfactory-quickjs-build-") as temp:
        objects = []
        # Compile verified sources directly; never reuse pre-existing objects or a
        # source-directory Makefile target that could select unverified build output.
        for source in (
            "quickjs.c",
            "dtoa.c",
            "libregexp.c",
            "libunicode.c",
            "cutils.c",
        ):
            obj = str(Path(temp) / (source + ".o"))
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-D_GNU_SOURCE",
                    '-DCONFIG_VERSION="2026-06-04"',
                    "-c",
                    str(args.source / source),
                    "-o",
                    obj,
                ],
                check=True,
            )
            objects.append(obj)
        subprocess.run(
            [
                "cc",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-isystem",
                str(args.source),
                str(Path(__file__).with_name("script_host.c")),
                *objects,
                "-lm",
                "-lpthread",
                "-o",
                str(args.output),
            ],
            check=True,
        )


if __name__ == "__main__":
    main()
