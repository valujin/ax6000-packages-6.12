#!/usr/bin/env python3
"""Compare named AArch64 struct/union layouts against the pinned mapd objects.

Usage: python3 verify-blob-abi.py /path/to/prepared-and-built/mapd
Needs host readelf and unstripped mapd.o. Normalizes GCC8 DWARF4 bit offsets
and GCC14 DWARF5 data_bit_offset; no target binaries are executed.
"""
import argparse
import re
import subprocess
import tempfile
from pathlib import Path


def layouts(path):
    output = subprocess.check_output(["readelf", "--debug-dump=info", str(path)], text=True)
    entries = {}
    stack = []
    current = None
    for line in output.splitlines():
        match = re.match(r" <(\d+)><([0-9a-f]+)>:.*?(?:\((DW_TAG_\w+)\))?$", line)
        if match:
            depth, address, tag = match.groups()
            depth = int(depth)
            current = {"tag": tag, "children": []}
            entries[int(address, 16)] = current
            stack = stack[:depth]
            if stack:
                stack[-1]["children"].append(current)
            stack.append(current)
            continue
        match = re.search(r"DW_AT_(\w+)\s*:\s*(.*)$", line)
        if match and current is not None:
            key, value = match.groups()
            if key == "name":
                current[key] = value.rsplit(": ", 1)[-1]
            elif key == "type":
                current[key] = int(re.search(r"<0x([0-9a-f]+)>", value).group(1), 16)
            elif key in {"byte_size", "bit_size", "bit_offset", "data_bit_offset", "data_member_location"}:
                current[key] = int(value, 0)

    result = {}
    for entry in entries.values():
        if entry["tag"] not in {"DW_TAG_structure_type", "DW_TAG_union_type"} or "name" not in entry or "byte_size" not in entry:
            continue
        members = {}
        for member in entry["children"]:
            if member["tag"] != "DW_TAG_member" or "name" not in member:
                continue
            bits = member.get("bit_size")
            offset = 8 * member.get("data_member_location", 0)
            if "data_bit_offset" in member:
                offset = member["data_bit_offset"]
            elif "bit_offset" in member:
                offset += 8 * member["byte_size"] - member["bit_offset"] - bits
            members[member["name"]] = (offset, bits)
        result[entry["name"]] = (entry["byte_size"], members)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    source = layouts(args.build_dir / "mapd.o")
    expected = {"own_1905_device": 342840, "mapd_global": 342960,
                "_1905_map_device": 1072, "radio_info_db": 1488}
    for name, size in expected.items():
        if source.get(name, (None,))[0] != size:
            raise SystemExit(f"unexpected source layout: {name}")
    objects = sorted((args.build_dir / "mapd_lib").rglob("*.o"))
    if len(objects) != 7:
        raise SystemExit("expected exactly seven pinned vendor objects")
    def compare(obj, label):
        vendor = layouts(obj)
        shared = source.keys() & vendor.keys()
        if not {"own_1905_device", "_1905_map_device", "radio_info_db"} <= shared:
            raise SystemExit(f"missing required DWARF types: {label}")
        differences = sorted(name for name in shared if source[name] != vendor[name])
        if differences:
            raise SystemExit(f"layout mismatch in {label}: {differences}")
        print(f"PASS {label}: {len(shared)} named layouts")

    for obj in objects:
        compare(obj, obj.relative_to(args.build_dir))
    # The linked archives differ from the loose objects; verify both sets.
    with tempfile.TemporaryDirectory(prefix="mapd-abi-") as scratch:
        for name in ("libmapd_core.a", "libmapd_steer_core.a"):
            archive = args.build_dir / name
            members = subprocess.check_output(["ar", "t", str(archive)], text=True).splitlines()
            if len(members) != (4 if name == "libmapd_core.a" else 3):
                raise SystemExit(f"unexpected archive members: {name}")
            for member in members:
                obj = Path(scratch) / Path(member).name
                obj.write_bytes(subprocess.check_output(["ar", "p", str(archive), member]))
                compare(obj, f"{name}({member})")


if __name__ == "__main__":
    main()
