"""Reading a file that another process is still writing, one byte cursor at a time.

Both things this wrapper watches — the findings a scan prints, and the callbacks an
out-of-band listener prints — arrive the same way: a line at a time, into a file, while a
process we started keeps appending. This is the single place that knows how to read such a
file without repeating a line or losing one.
"""

from __future__ import annotations

from pathlib import Path


def read_text_since(path: str | Path, offset: int = 0) -> tuple[str, int]:
    """Complete text from `offset` on, and the offset to use next time.

    Only whole lines are handed back: a file whose last line has no newline yet is being
    written right now, and half a line parses as nothing. A file that shrank has been
    replaced or truncated, so the offset no longer means anything and reading starts over —
    a replacement of the same size or larger is not detected, which is sound because nothing
    writes these files but the process that owns them, in a directory of its own.
    """
    log = Path(path)
    if not log.exists():
        return "", offset

    size = log.stat().st_size
    if size < offset:
        offset = 0

    with log.open("rb") as handle:
        handle.seek(offset)
        chunk = handle.read()

    complete = chunk
    if chunk and not chunk.endswith(b"\n"):
        cut = chunk.rfind(b"\n")
        complete = chunk[: cut + 1] if cut != -1 else b""

    return complete.decode("utf-8", "replace"), offset + len(complete)
