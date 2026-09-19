"""Shared firmware provider link inspection."""
import re
import subprocess
from collections import defaultdict

SOFTWARE = {"aes", "cmac", "ccm", "p256", "ecdsa", "elliptic-curve", "sha2", "hmac"}


def inspect_link(binary, link_map, hardware):
    symbols = subprocess.run(
        ["arm-none-eabi-nm", "-S", "-C", str(binary)],
        check=True, capture_output=True, text=True,
    ).stdout
    names = {line.split()[-1] for line in symbols.splitlines() if line.split()}
    allocators = sorted(names & {"malloc", "calloc", "realloc", "free"})
    if allocators:
        raise SystemExit(f"vendor code requires C allocation: {allocators}")
    if hardware and any(f"{crate.replace('-', '_')}::" in symbols for crate in SOFTWARE):
        raise SystemExit("hardware firmware links RustCrypto implementation symbols")
    archives = defaultdict(int)
    members = defaultdict(int)
    for line in link_map.read_text().splitlines():
        # LLD input sections carry the archive(member) identity; symbol rows do not.
        match = re.search(r"(lib[^/\s]+\.a)\(([^)]+)\):\(\.(?:text|rodata)(?:[.)])", line)
        if match:
            fields = line.split()
            size = int(fields[2], 16)
            archives[match[1]] += size
            members[f"{match[1]}({match[2]})"] += size
    if hardware and not any(name.startswith("libnrf_cc310_platform_") for name in archives):
        raise SystemExit("hardware link map is missing CC310 platform input sections")
    return {
        "c_allocator_symbols": allocators,
        "archive_text_rodata_bytes": dict(sorted(archives.items())),
        "largest_archive_members": dict(sorted(members.items(), key=lambda item: (-item[1], item[0]))[:10]),
        "non_profile_algorithm_symbols": sorted(name for name in names
            if re.search(r"chacha|poly1305", name, re.IGNORECASE)),
    }

