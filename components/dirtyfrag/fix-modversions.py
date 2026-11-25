#!/usr/bin/env python3

"""Rewrite a module's symbol CRCs from the running device's kernel image."""

import argparse
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile


VERSION_ENTRY_SIZE = 64
VERSION_NAME_SIZE = 56


def read_kallsyms(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in path.read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        symbols[fields[2]] = int(fields[0], 16)
    return symbols


def read_image_u32(image_path: Path, address: int) -> int:
    with image_path.open("rb") as image_file:
        elf = ELFFile(image_file)
        for section in elf.iter_sections():
            section_start = section["sh_addr"]
            section_end = section_start + section["sh_size"]
            if section_start <= address < section_end:
                section_offset = address - section_start
                image_file.seek(section["sh_offset"] + section_offset)
                return struct.unpack("<I", image_file.read(4))[0]
    raise ValueError(f"address {address:#x} is outside the kernel image")


def expected_crc(
    symbol_name: str,
    kallsyms: dict[str, int],
    image_path: Path,
) -> int:
    export_name = f"__ksymtab_{symbol_name}"
    export_address = kallsyms.get(export_name)
    if export_address is None:
        raise ValueError(f"{export_name} is not exported by the device kernel")

    normal_start = kallsyms["__start___ksymtab"]
    normal_end = kallsyms["__start___ksymtab_gpl"]
    gpl_start = normal_end
    gpl_end = kallsyms["__stop___ksymtab_gpl"]

    if normal_start <= export_address < normal_end:
        section_start = normal_start
        section_end = normal_end
        crc_table_start = kallsyms["__start___kcrctab"]
    elif gpl_start <= export_address < gpl_end:
        section_start = gpl_start
        section_end = gpl_end
        crc_table_start = kallsyms["__start___kcrctab_gpl"]
    else:
        raise ValueError(f"{export_name} is outside the kernel export tables")

    export_count = sum(
        section_start <= address < section_end
        for name, address in kallsyms.items()
        if name.startswith("__ksymtab_")
    )
    if export_count == 0 or (section_end - section_start) % export_count:
        raise ValueError("cannot derive the kernel symbol entry stride")

    entry_stride = (section_end - section_start) // export_count
    symbol_index = (export_address - section_start) // entry_stride
    return read_image_u32(image_path, crc_table_start + symbol_index * 4)


def rewrite_versions(
    module_path: Path,
    output_path: Path,
    kallsyms_path: Path,
    image_path: Path,
) -> None:
    kallsyms = read_kallsyms(kallsyms_path)
    module_data = bytearray(module_path.read_bytes())

    with module_path.open("rb") as module_file:
        module_elf = ELFFile(module_file)
        version_section = module_elf.get_section_by_name("__versions")
        if version_section is None:
            raise ValueError(f"{module_path} has no __versions section")

        section_offset = version_section["sh_offset"]
        section_data = version_section.data()
        if len(section_data) % VERSION_ENTRY_SIZE != 0:
            raise ValueError("__versions has an unexpected size")

        print(f"{'symbol':32s} {'module':>10s} {'device':>10s}")
        for entry_offset in range(0, len(section_data), VERSION_ENTRY_SIZE):
            current_crc, = struct.unpack_from("<I", section_data, entry_offset)
            raw_name = section_data[
                entry_offset + 8:entry_offset + 8 + VERSION_NAME_SIZE
            ]
            symbol_name = raw_name.split(b"\0", 1)[0].decode()
            device_crc = expected_crc(symbol_name, kallsyms, image_path)
            print(f"{symbol_name:32s} {current_crc:#010x} {device_crc:#010x}")

            output_offset = section_offset + entry_offset
            struct.pack_into("<II", module_data, output_offset, device_crc, 0)

    output_path.write_bytes(module_data)
    print(f"wrote {output_path}")


def main() -> None:
    root = Path(__file__).resolve().parent
    firmware = root.parent / "firmware-4.2.0.252"

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "module",
        type=Path,
        help="module to rewrite",
    )
    parser.add_argument(
        "output",
        type=Path,
        help="rewritten module",
    )
    parser.add_argument(
        "--kallsyms",
        type=Path,
        default=firmware / "symbols/dby2-4.2.0.252.kallsyms",
    )
    parser.add_argument(
        "--image",
        type=Path,
        default=firmware / "analysis/Image-4.2.0.252.elf",
    )
    args = parser.parse_args()

    rewrite_versions(args.module, args.output, args.kallsyms, args.image)


if __name__ == "__main__":
    main()
