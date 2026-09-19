#!/usr/bin/env python3
"""Check local inline Markdown link destinations in public documentation."""
import pathlib
import re
from urllib.parse import unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]


def missing_links(path):
    text = re.sub(r"```.*?```", "", path.read_text(), flags=re.DOTALL)
    for match in re.finditer(r"\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)", text):
        target = match.group(1).strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        destination = (ROOT if parsed.path.startswith("/") else path.parent) / unquote(parsed.path).lstrip("/")
        if not destination.exists():
            yield target


def main():
    paths = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").rglob("*.md"))
    failures = [f"{path.relative_to(ROOT)}: {target}" for path in paths for target in missing_links(path)]
    if failures:
        raise SystemExit("Broken local documentation links:\n" + "\n".join(failures))
    print(f"PASS: local link destinations in {len(paths)} documents")


if __name__ == "__main__":
    main()
