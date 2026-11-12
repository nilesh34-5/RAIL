"""Stages S1 (protocol separation) and S6 (re-origination).

S1 terminates the incoming session and hands the extracted application object to
the pipeline, discarding all transport context.  S6 originates a *fresh*
delivery of the recovered object on the destination network.  In this reference
implementation both sides use the local filesystem as the "application
protocol": S1 reads a spooled object, S6 writes it into an output directory.  The
interface is narrow so a real deployment can substitute an
SMTP/HTTP/SMB proxy without touching the rest of the pipeline.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .models import TransferObject


class ProtocolBreak:
    """Filesystem-backed protocol break (replaceable with a real proxy)."""

    def __init__(self, spool_dir: Path | None = None, out_dir: Path | None = None) -> None:
        self.spool_dir = Path(spool_dir) if spool_dir else None
        self.out_dir = Path(out_dir) if out_dir else None
        if self.out_dir:
            self.out_dir.mkdir(parents=True, exist_ok=True)

    # -- S1 -----------------------------------------------------------------
    @staticmethod
    def extract_file(path: Path) -> TransferObject:
        """S1: terminate a 'session' (here: a file) and extract the object."""
        p = Path(path)
        return TransferObject(name=p.name, data=p.read_bytes(), src_protocol="file")

    def iter_spool(self) -> Iterator[TransferObject]:
        """Yield every object currently spooled for transfer."""
        if not self.spool_dir:
            return
        for p in sorted(self.spool_dir.iterdir()):
            # skip hidden/placeholder files (.gitkeep, editor swap files, ...)
            if p.is_file() and not p.name.startswith("."):
                yield self.extract_file(p)

    # -- S6 -----------------------------------------------------------------
    def reoriginate(self, obj_name: str, data: bytes) -> Path:
        """S6: originate a fresh delivery on the destination network."""
        if not self.out_dir:
            raise RuntimeError("no output directory configured for re-origination")
        dest = self.out_dir / obj_name
        dest.write_bytes(data)
        return dest
