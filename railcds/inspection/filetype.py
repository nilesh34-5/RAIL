"""File-type identification and polyglot detection.

Koch et al. (cited in the paper) show that polyglot files - valid as two
different types at once - defeat the file-type identification that later
inspection stages depend on.  This detector:

  1. Identifies the object's type with libmagic (python-magic) when available,
     falling back to a built-in magic-byte table otherwise.
  2. Scans for *multiple* independent format signatures.  A file that is
     simultaneously, say, a valid ZIP and a valid PDF (a classic polyglot) is
     flagged with high confidence.
  3. Flags a mismatch between the declared extension and the detected type.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..models import TransferObject
from .base import Detector

try:
    import magic  # python-magic / python-magic-bin
    _HAVE_MAGIC = True
except Exception:      # noqa: BLE001
    _HAVE_MAGIC = False

# (label, header signature, may-appear-anywhere marker)
_SIGNATURES: List[Tuple[str, bytes]] = [
    ("pe/exe", b"MZ"),
    ("elf", b"\x7fELF"),
    ("pdf", b"%PDF-"),
    ("zip", b"PK\x03\x04"),
    ("gzip", b"\x1f\x8b"),
    ("rar", b"Rar!\x1a\x07"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpg", b"\xff\xd8\xff"),
    ("gif", b"GIF8"),
    ("bmp", b"BM"),
    ("class", b"\xca\xfe\xba\xbe"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("ole", b"\xd0\xcf\x11\xe0"),
]

# markers that, when embedded past the header, indicate a second personality
_EMBEDDED_MARKERS: List[Tuple[str, bytes]] = [
    ("pdf", b"%PDF-"),
    ("zip", b"PK\x03\x04"),
    ("html", b"<html"),
    ("html", b"<!DOCTYPE html"),
    ("script", b"<script"),
    ("pe/exe", b"This program cannot be run in DOS mode"),
    ("elf", b"\x7fELF"),
]

_EXT_TO_TYPE = {
    "pdf": "pdf", "zip": "zip", "exe": "pe/exe", "dll": "pe/exe",
    "png": "png", "jpg": "jpg", "jpeg": "jpg", "gif": "gif",
    "gz": "gzip", "docx": "zip", "xlsx": "zip", "pptx": "zip",
}


class FileTypeDetector(Detector):
    name = "file_type"

    def setup(self) -> None:
        self._magic = magic.Magic(mime=False) if _HAVE_MAGIC else None

    def _header_type(self, data: bytes) -> str:
        for label, sig in _SIGNATURES:
            if data.startswith(sig):
                return label
        return "unknown"

    def score(self, obj: TransferObject) -> Tuple[float, str]:
        data = obj.data
        if not data:
            return 0.0, "empty"

        header_type = self._header_type(data)
        libmagic_desc = ""
        if self._magic is not None:
            try:
                libmagic_desc = self._magic.from_buffer(data[:8192])
            except Exception:      # noqa: BLE001
                libmagic_desc = ""

        # --- polyglot: count distinct personalities present -----------------
        personalities = set()
        if header_type != "unknown":
            personalities.add(header_type)
        body = data[8:]            # skip the primary header
        for label, marker in _EMBEDDED_MARKERS:
            if marker in body:
                personalities.add(label)

        risk = 0.0
        notes = [f"header={header_type}"]
        if libmagic_desc:
            notes.append(f"magic='{libmagic_desc[:48]}'")

        if len(personalities) >= 2:
            risk = 0.85
            notes.append(f"POLYGLOT: {sorted(personalities)}")

        # --- extension vs content mismatch ---------------------------------
        ext = obj.name.rsplit(".", 1)[-1].lower() if "." in obj.name else ""
        expected = _EXT_TO_TYPE.get(ext)
        if expected and header_type not in ("unknown", expected):
            risk = max(risk, 0.5)
            notes.append(f"ext .{ext} != content {header_type}")

        # an object claiming to be an image but starting with MZ/ELF etc.
        if ext in ("png", "jpg", "jpeg", "gif") and header_type in ("pe/exe", "elf"):
            risk = max(risk, 0.9)
            notes.append("executable masquerading as image")

        return risk, "; ".join(notes)
