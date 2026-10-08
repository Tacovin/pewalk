"""
Runs pewalk -j on a bunch of PE files and compares the output with pefile.
pefile is the reference here, if they disagree it's most likely my bug.

    python tests/check_pefile.py build/pewalk.exe C:/Windows/System32/*.dll
"""
import glob
import json
import os
import subprocess
import sys

import pefile


def rich_checksum(data, start, entries):
    csum = start
    for i in range(start):
        if 0x3C <= i < 0x40:
            continue
        b = data[i]
        n = i % 32
        csum += ((b << n) | (b >> (32 - n))) & 0xFFFFFFFF if n else b
        csum &= 0xFFFFFFFF
    for compid, count in entries:
        n = count % 32
        v = ((compid << n) | (compid >> (32 - n))) & 0xFFFFFFFF if n else compid
        csum = (csum + v) & 0xFFFFFFFF
    return csum


def compare(tool, path):
    out = subprocess.run([tool, "-j", path], capture_output=True, text=True)
    if out.returncode != 0:
        return ["pewalk failed: " + out.stderr.strip()]
    got = json.loads(out.stdout)

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
    ])
    errs = []

    oh = pe.OPTIONAL_HEADER
    if got["entry_rva"] != oh.AddressOfEntryPoint:
        errs.append(f"entry {got['entry_rva']:#x} != {oh.AddressOfEntryPoint:#x}")
    if got["image_base"] != oh.ImageBase:
        errs.append("image base")

    if len(got["sections"]) != len(pe.sections):
        errs.append("section count")
    for a, b in zip(got["sections"], pe.sections):
        name = b.Name.rstrip(b"\0").decode("latin-1")
        if a["name"] != name or a["va"] != b.VirtualAddress or a["raw_size"] != b.SizeOfRawData:
            errs.append(f"section {name}")
        if abs(a["entropy"] - b.get_entropy()) > 0.001:
            errs.append(f"entropy {name} {a['entropy']} vs {b.get_entropy()}")

    want = []
    for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in d.imports:
            # pefile fills in names for ordinals of ws2_32/oleaut32 from its
            # own table, pewalk doesn't, so compare the ordinal there
            if imp.import_by_ordinal:
                want.append(imp.ordinal)
            else:
                want.append(imp.name.decode("latin-1") if imp.name else None)
    have = [i.get("name", i.get("ordinal")) for i in got["imports"]]
    if want != have:
        errs.append(f"imports differ ({len(have)} vs {len(want)})")

    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp:
        # pefile cuts very long (c++ mangled) names, so compare a prefix
        names = sorted(s.name.decode("latin-1")[:256] for s in exp.symbols if s.name)
        if names != sorted(n[:256] for n in got["exports"]["names"]):
            errs.append("export names")

    rich = pe.parse_rich_header()
    if bool(rich) != bool(got["rich"]):
        errs.append("rich presence")
    elif rich:
        vals = rich["values"]
        # pefile assumes DanS is right at 0x80. With a longer DOS stub
        # (tcblaunch.exe) it decodes the stub as entries until it hits DanS
        if 0x536E6144 in vals:
            vals = vals[vals.index(0x536E6144) + 4:]
        pairs = list(zip(vals[0::2], vals[1::2]))
        mine = [((e["prodid"] << 16) | e["build"], e["count"]) for e in got["rich"]["entries"]]
        if pairs != mine:
            errs.append("rich entries")
        if rich["checksum"] != got["rich"]["key"]:
            errs.append("rich key")
        data = pe.__data__
        start = None
        key = rich["checksum"]
        for off in range(0x80, pe.DOS_HEADER.e_lfanew, 4):
            if int.from_bytes(data[off:off + 4], "little") ^ key == 0x536E6144:
                start = off
                break
        ok = start is not None and rich_checksum(data, start, pairs) == key
        if ok != got["rich"]["checksum_ok"]:
            errs.append("rich checksum verdict")

    ov = pe.get_overlay_data_start_offset()
    mine_ov = got["overlay"]["offset"] if got["overlay"] else None
    if ov != mine_ov:
        errs.append(f"overlay {mine_ov} vs {ov}")

    return errs


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    tool = os.path.abspath(sys.argv[1])
    files = []
    for pat in sys.argv[2:]:
        files += glob.glob(pat) or [pat]

    bad = 0
    tested = 0
    for f in files:
        try:
            errs = compare(tool, f)
        except pefile.PEFormatError:
            continue
        tested += 1
        if errs:
            bad += 1
            print(f"FAIL {f}: {'; '.join(errs)}")

    print(f"{tested - bad}/{tested} files match")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
