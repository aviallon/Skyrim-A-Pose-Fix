#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0
"""Build or verify an Amethyst/MO2-installable mod archive for APoseFix.

The archive must mirror the layout of the upstream release, which is what a mod
manager sees after installing it. Taken from the installed mod folder:

    SKSE/Plugins/APoseFix.dll                            the plugin
    meshes/actors/character/behaviors/dummybehavior.hkx  the fallback graph the
                                                         plugin redirects to when a
                                                         behaviour graph cannot load
    SKSE/Plugins/APoseFix/Settings.ini                   optional, if non-empty

Crucially the archive has NO wrapper directory: the archive root *is* the mod root,
so a manager installs it as a single mod. A stray top-level folder would make the
mod install as a folder named after itself, with the real paths nested inside.

Usage:
  mod_archive.py build --stage DIR --out FILE [--version V]
  mod_archive.py check FILE
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import zipfile

REQUIRED = [
    "SKSE/Plugins/APoseFix.dll",
    "meshes/actors/character/behaviors/dummybehavior.hkx",
]
OPTIONAL = [
    "SKSE/Plugins/APoseFix/Settings.ini",
]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build(stage: str, out: str, version: str | None) -> int:
    if not os.path.isdir(stage):
        print(f"  ERROR: no staging dir {stage}")
        return 1
    missing = [p for p in REQUIRED if not os.path.isfile(os.path.join(stage, *p.split("/")))]
    if missing:
        for m in missing:
            print(f"  ERROR: required file missing from staging: {m}")
        return 1

    members: list[tuple[str, str]] = []
    for rel in REQUIRED + OPTIONAL:
        src = os.path.join(stage, *rel.split("/"))
        if os.path.isfile(src):
            members.append((rel, src))

    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel, src in members:
            # arcname has no leading './' and no wrapper directory
            z.write(src, rel)

    print(f"  built {out}")
    print(f"  version: {version or 'unversioned'}")
    for rel, src in members:
        print(f"    {rel:52s} {os.path.getsize(src):>9} bytes  sha256 {_sha256(src)[:16]}…")
    return check(out)


def check(path: str) -> int:
    if not os.path.isfile(path):
        print(f"  ERROR: no such archive {path}")
        return 1
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        infos = {i.filename: i for i in z.infolist()}
    print(f"  checking {path} ({len(names)} entries, {os.path.getsize(path)} bytes)")

    failures: list[str] = []
    for rel in REQUIRED:
        if rel not in names:
            failures.append(f"missing required entry: {rel}")

    # No wrapper directory: at least one required entry must sit at the archive root
    # path directly, and every entry must be under a known top-level dir.
    tops = {n.split("/", 1)[0] for n in names if "/" in n}
    if not tops:
        failures.append("archive looks empty or flat")
    allowed_tops = {"SKSE", "meshes"}
    unexpected = {t for t in tops if t not in allowed_tops}
    if unexpected:
        failures.append(
            f"unexpected top-level entries {sorted(unexpected)} - the archive root must be the "
            f"mod root (SKSE/, meshes/), not a wrapper folder"
        )
    if len(tops) == 1 and next(iter(tops)) not in allowed_tops:
        failures.append(f"archive appears wrapped in a '{next(iter(tops))}/' directory")

    for n in sorted(names):
        if n.endswith("/"):
            continue
        print(f"    {n:52s} {infos[n].file_size:>9} bytes")

    if failures:
        for f in failures:
            print(f"  FAIL: {f}")
        return 1
    print("  OK: archive root is the mod root; required entries present")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--stage", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--version")
    c = sub.add_parser("check")
    c.add_argument("archive")
    args = ap.parse_args()
    if args.cmd == "build":
        return build(args.stage, args.out, args.version)
    return check(args.archive)


if __name__ == "__main__":
    sys.exit(main())
