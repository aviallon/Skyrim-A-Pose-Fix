#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0
"""Verify the SKSE version declaration exported by a built SKSE plugin DLL.

What this checks, and why the claim is narrow: it asserts only that the exported
``SKSEPlugin_Version`` struct is well formed (dataVersion == 1) and declares Address
Library independence. It does NOT assert the AddressLibraryV5 bit - see the note in
``report()``: V5 records which Address Library id space the plugin's ids came from,
and plugins without it load fine on 1.7.104.

"CI is green" is not "the plugin loads", and "the plugin loads" is not "the plugin
works" - skse64.log is the evidence for the second, and the game is the evidence for
the third.

The exported symbol ``SKSEPlugin_Version`` is a *data* export pointing at the
plugin's version struct; PE does not distinguish data from code exports, so the
function RVA in the export table is the struct address.

Usage:
  check_skse_version.py path/to/Plugin.dll
  check_skse_version.py --scan /path/to/SKSE/Plugins
"""

from __future__ import annotations

import argparse
import struct
import sys

# PluginVersionData field offsets (SKSE ABI). The static_asserts in
# CommonLibSSE-NG's include/SKSE/Interfaces.h pin these.
OFF_DATA_VERSION = 0x000
OFF_PLUGIN_VERSION = 0x004
OFF_PLUGIN_NAME = 0x008  # char[256]
OFF_AUTHOR = 0x108  # char[256]
OFF_EMAIL = 0x208  # char[252]
OFF_INDEPENDENCE_EX = 0x304  # std::uint32_t
OFF_INDEPENDENCE = 0x308  # std::uint32_t
OFF_COMPATIBLE = 0x30C  # std::uint32_t[16]
OFF_XSE_MINIMUM = 0x34C  # std::uint32_t
STRUCT_SIZE = 0x350

K_VERSION_INDEPENDENT_ADDRESS_LIBRARY_POST_AE = 1 << 0
K_VERSION_INDEPENDENT_EX_ADDRESS_LIBRARY_V5 = 1 << 1
K_VERSION_INDEPENDENT_EX_NO_STRUCT_USE = 1 << 0


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


class Pe:
    """Minimal PE reader: enough to map an export RVA to a file offset."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE file (no MZ)")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file (no PE signature)")
        coff = pe + 4
        n_sections = struct.unpack_from("<H", data, coff + 2)[0]
        size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        self.magic = "PE32+" if magic == 0x20B else "PE32"
        dd_off = opt + (0x70 if magic == 0x20B else 0x60)
        self.export_rva = struct.unpack_from("<I", data, dd_off)[0]
        self.sections = []
        sec = opt + size_opt
        for i in range(n_sections):
            base = sec + i * 40
            name = _cstr(data[base : base + 8])
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
            self.sections.append((vaddr, max(vsize, rawsize), rawptr, name))

    def rva_to_off(self, rva: int) -> int:
        for vaddr, size, rawptr, _name in self.sections:
            if vaddr <= rva < vaddr + size:
                return rawptr + (rva - vaddr)
        raise ValueError(f"rva 0x{rva:x} is not in any section")

    def _rva_cstr(self, rva: int) -> str:
        off = self.rva_to_off(rva)
        end = self.data.index(b"\0", off)
        return self.data[off:end].decode("utf-8", "replace")

    def export(self, name: str) -> int:
        """Return the RVA of the named export, or raise KeyError."""
        off = self.rva_to_off(self.export_rva)
        # IMAGE_EXPORT_DIRECTORY (40 bytes): MajorVersion/MinorVersion are WORDs.
        (
            _chars, _tds, _major, _minor, _name_rva, _base,
            n_func, n_names, addr_func, addr_names, addr_ords,
        ) = struct.unpack_from("<IIHHIIIIIII", self.data, off)
        names_off = self.rva_to_off(addr_names)
        funcs_off = self.rva_to_off(addr_func)
        ords_off = self.rva_to_off(addr_ords)
        for i in range(n_names):
            if self._rva_cstr(struct.unpack_from("<I", self.data, names_off + i * 4)[0]) == name:
                ordinal = struct.unpack_from("<H", self.data, ords_off + i * 2)[0]
                if ordinal >= n_func:
                    raise ValueError(f"export {name}: ordinal {ordinal} out of range")
                return struct.unpack_from("<I", self.data, funcs_off + ordinal * 4)[0]
        raise KeyError(name)


def report(dll: str, verbose: bool = True) -> int:
    data = open(dll, "rb").read()
    pe = Pe(data)
    try:
        rva = pe.export("SKSEPlugin_Version")
    except KeyError:
        print(f"  {dll}: no SKSEPlugin_Version export")
        return 1
    off = pe.rva_to_off(rva)
    v = data[off : off + STRUCT_SIZE]
    if len(v) < STRUCT_SIZE:
        print(f"  {dll}: version struct truncated")
        return 1

    def u32(o: int) -> int:
        return struct.unpack_from("<I", v, o)[0]

    dv, pv = u32(OFF_DATA_VERSION), u32(OFF_PLUGIN_VERSION)
    ex, ind, xse = u32(OFF_INDEPENDENCE_EX), u32(OFF_INDEPENDENCE), u32(OFF_XSE_MINIMUM)
    name = _cstr(v[OFF_PLUGIN_NAME : OFF_PLUGIN_NAME + 256])
    author = _cstr(v[OFF_AUTHOR : OFF_AUTHOR + 256])

    if not verbose:
        print(
            f"  {name or '(unnamed)':28s} dataVersion={dv} ind=0x{ind:x} ex=0x{ex:x} "
            f"V5={'yes' if ex & K_VERSION_INDEPENDENT_EX_ADDRESS_LIBRARY_V5 else 'NO ':3s} "
            f"{author[:22]}"
        )
    else:
        print(f"  file        : {dll} ({len(data)} bytes, {pe.magic})")
        print(f"  SKSEPlugin_Version @ rva 0x{rva:x} (file 0x{off:x})")
        print(f"  dataVersion            : {dv}")
        print(f"  pluginVersion          : {pv}")
        print(f"  pluginName             : {name!r}")
        print(f"  author                 : {author!r}")
        print(f"  versionIndependence    : 0x{ind:x}  (AddressLibrary bit: "
              f"{bool(ind & K_VERSION_INDEPENDENT_ADDRESS_LIBRARY_POST_AE)})")
        print(f"  versionIndependenceEx  : 0x{ex:x}  (V5 bit: "
              f"{bool(ex & K_VERSION_INDEPENDENT_EX_ADDRESS_LIBRARY_V5)}, NoStructUse bit: "
              f"{bool(ex & K_VERSION_INDEPENDENT_EX_NO_STRUCT_USE)})")
        print(f"  xseMinimum             : {xse}")

    failures = []
    if dv != 1:
        failures.append(f"dataVersion is {dv}, expected 1")
    if not ind & K_VERSION_INDEPENDENT_ADDRESS_LIBRARY_POST_AE:
        failures.append("versionIndependence lacks the AddressLibrary(PostAE) bit")
    # NOTE: the V5 bit is deliberately NOT asserted. It declares which Address Library
    # *id space* the plugin's ids were compiled against; it is not a load gate. Measured
    # on a working 1.7.104 install: of 40 installed plugins, many that load fine declare
    # versionIndependenceEx=0x1 (no V5) - CrashLogger, BetterJumpingSE, ConsoleUtilSSE -
    # while others declare 0x3. Both kinds load. See skse64.log: SKSE 'checks' then
    # 'loads' them with no incompatible/disabled line.
    if not ex & K_VERSION_INDEPENDENT_EX_ADDRESS_LIBRARY_V5:
        print("  NOTE: no V5 bit (declares the pre-format-5 id space) - not a load failure")
    if failures:
        for f in failures:
            print(f"  FAIL: {f}")
        return 1
    if verbose:
        print("  OK: declaration is loadable (dataVersion 1 + AddressLibrary bit)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dll", nargs="?")
    ap.add_argument("--scan", metavar="DIR", help="report every SKSE plugin DLL in DIR")
    args = ap.parse_args()

    if args.scan:
        import glob
        import os

        dlls = sorted(glob.glob(os.path.join(args.scan, "*.dll")))
        print(f"  scanning {len(dlls)} DLL(s) in {args.scan}")
        for d in dlls:
            try:
                report(d, verbose=False)
            except Exception as exc:  # noqa: BLE001 - a scan should not abort
                print(f"  {os.path.basename(d):28s} unreadable: {exc}")
        return 0
    if not args.dll:
        ap.error("a DLL path or --scan DIR is required")
    return report(args.dll)


if __name__ == "__main__":
    sys.exit(main())
