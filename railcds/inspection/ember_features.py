"""EMBER v2 (feature_version=2) feature extraction, adapted to LIEF 1.0.

This reproduces the 2381-dimensional feature vector expected by the pretrained
EMBER LightGBM model (H. Anderson and P. Roth, "EMBER: An Open Dataset for
Training Static PE Malware Machine Learning Models", 2018).  The group order,
dimensions and FeatureHasher sizes match the reference implementation so the
official ``ember_model_2018.txt`` booster can score the vector directly.

Feature groups (2381 total):
    ByteHistogram          256
    ByteEntropyHistogram   256
    StringExtractor        104
    GeneralFileInfo         10
    HeaderFileInfo          62
    SectionInfo            255
    ImportsInfo           1280
    ExportsInfo            128
    DataDirectories         30

LIEF 1.0's API differs from the 0.9/0.10 series EMBER was authored against.
The byte, entropy, string and import/library features - which carry most of the
model's discriminative power - are byte-exact or plain-string and therefore
match training.  A handful of enum-derived hashed features may differ slightly
across LIEF versions; this is documented in docs/MODELS.md.
"""
from __future__ import annotations

import re
from typing import List, Optional

import numpy as np
from sklearn.feature_extraction import FeatureHasher

import lief

# silence LIEF's verbose logging
try:
    lief.logging.disable()
except Exception:      # noqa: BLE001
    pass


# ---------------------------------------------------------------------------
# Byte-level groups (LIEF-independent)
# ---------------------------------------------------------------------------
def _byte_histogram(bytez: bytes) -> np.ndarray:
    a = np.frombuffer(bytez, dtype=np.uint8)
    counts = np.bincount(a, minlength=256)
    total = counts.sum()
    return (counts / total).astype(np.float32) if total else counts.astype(np.float32)


def _byte_entropy_histogram(bytez: bytes, step: int = 1024, window: int = 2048) -> np.ndarray:
    output = np.zeros((16, 16), dtype=np.int64)
    a = np.frombuffer(bytez, dtype=np.uint8)

    def bin_counts(block: np.ndarray):
        c = np.bincount(block >> 4, minlength=16)          # coarse 16-bin hist
        p = c.astype(np.float32) / window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2            # 4 high bits only
        Hbin = int(H * 2)
        if Hbin == 16:
            Hbin = 15
        return Hbin, c

    if a.shape[0] < window:
        Hbin, c = bin_counts(a)
        output[Hbin, :] += c
    else:
        shape = (a.shape[0] - window + 1, window)
        strides = (a.strides[0], a.strides[0])
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            Hbin, c = bin_counts(block)
            output[Hbin, :] += c

    flat = output.flatten().astype(np.float32)
    s = flat.sum()
    return flat / s if s else flat


_ALLSTRINGS = re.compile(rb"[\x20-\x7f]{5,}")
_PATHS = re.compile(rb"c:\\", re.IGNORECASE)
_URLS = re.compile(rb"https?://", re.IGNORECASE)
_REGISTRY = re.compile(rb"HKEY_")
_MZ = re.compile(rb"MZ")


def _string_features(bytez: bytes) -> np.ndarray:
    allstrings = _ALLSTRINGS.findall(bytez)
    if allstrings:
        string_lengths = [len(s) for s in allstrings]
        avlength = sum(string_lengths) / len(string_lengths)
        as_shifted = np.concatenate([np.frombuffer(s, dtype=np.uint8) for s in allstrings])
        as_shifted = as_shifted - ord(" ")
        c = np.bincount(as_shifted, minlength=96)
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = float(np.sum(-p[wh] * np.log2(p[wh])))
    else:
        avlength = 0.0
        c = np.zeros((96,), dtype=np.float32)
        csum = 0
        H = 0.0
    printabledist = (c.astype(np.float32) / csum) if csum else c.astype(np.float32)
    return np.hstack([
        len(allstrings), avlength, csum,
        printabledist,                          # 96
        H,
        len(_PATHS.findall(bytez)),
        len(_URLS.findall(bytez)),
        len(_REGISTRY.findall(bytez)),
        len(_MZ.findall(bytez)),
    ]).astype(np.float32)


# ---------------------------------------------------------------------------
# PE-structural groups (LIEF 1.0)
# ---------------------------------------------------------------------------
def _hasher(dim: int, pairs) -> np.ndarray:
    return FeatureHasher(dim, input_type="pair").transform([pairs]).toarray()[0].astype(np.float32)


def _hasher_str(dim: int, strings) -> np.ndarray:
    return FeatureHasher(dim, input_type="string").transform([strings]).toarray()[0].astype(np.float32)


def _general_info(bytez: bytes, b) -> np.ndarray:
    if b is None:
        return np.zeros(10, dtype=np.float32)
    imports = 0
    try:
        imports = sum(len(list(lib.entries)) for lib in b.imports)
    except Exception:      # noqa: BLE001
        imports = 0
    try:
        exports = len(list(b.exported_functions))
    except Exception:      # noqa: BLE001
        exports = 0
    vsize = getattr(b, "virtual_size", None)
    if vsize is None:
        vsize = getattr(b.optional_header, "sizeof_image", 0)
    return np.hstack([
        len(bytez),
        vsize,
        int(bool(getattr(b, "has_debug", False))),
        exports,
        imports,
        int(bool(getattr(b, "has_relocations", False))),
        int(bool(getattr(b, "has_resources", False))),
        int(bool(getattr(b, "has_signatures", getattr(b, "has_signature", False)))),
        int(bool(getattr(b, "has_tls", False))),
        len(list(getattr(b, "symbols", []) or [])),
    ]).astype(np.float32)


def _header_info(b) -> np.ndarray:
    if b is None:
        return np.zeros(62, dtype=np.float32)
    h = b.header
    oh = b.optional_header
    timestamp = getattr(h, "time_date_stamps", getattr(h, "time_date_stamp", 0))
    machine = str(h.machine)
    characteristics = [str(c) for c in getattr(h, "characteristics_list", [])]
    subsystem = str(oh.subsystem)
    dll_char = [str(c) for c in getattr(oh, "dll_characteristics_lists", [])]
    magic = str(getattr(oh, "magic", ""))
    return np.hstack([
        timestamp,
        _hasher_str(10, [machine]),
        _hasher_str(10, characteristics),
        _hasher_str(10, [subsystem]),
        _hasher_str(10, dll_char),
        _hasher_str(10, [magic]),
        oh.major_image_version, oh.minor_image_version,
        oh.major_linker_version, oh.minor_linker_version,
        oh.major_operating_system_version, oh.minor_operating_system_version,
        oh.major_subsystem_version, oh.minor_subsystem_version,
        oh.sizeof_code, oh.sizeof_headers,
        getattr(oh, "sizeof_heap_commit", 0),
    ]).astype(np.float32)


def _entry_section_name(b) -> str:
    try:
        imagebase = b.optional_header.imagebase
        entry_rva = b.entrypoint - imagebase
        for s in b.sections:
            if s.virtual_address <= entry_rva < s.virtual_address + s.virtual_size:
                return s.name
    except Exception:      # noqa: BLE001
        pass
    # fall back to first executable section
    try:
        for s in b.sections:
            if any("MEM_EXECUTE" in str(c) for c in s.characteristics_lists):
                return s.name
    except Exception:      # noqa: BLE001
        pass
    return ""


def _section_info(b) -> np.ndarray:
    if b is None:
        return np.zeros(255, dtype=np.float32)
    sections = []
    for s in b.sections:
        props = [str(c) for c in getattr(s, "characteristics_lists", [])]
        sections.append({
            "name": s.name, "size": int(s.size),
            "entropy": float(getattr(s, "entropy", 0.0) or 0.0),
            "vsize": int(s.virtual_size), "props": props,
        })
    entry = _entry_section_name(b)
    general = [
        len(sections),
        sum(1 for s in sections if s["size"] == 0),
        sum(1 for s in sections if s["name"] == ""),
        sum(1 for s in sections
            if any("MEM_READ" in p for p in s["props"])
            and any("MEM_EXECUTE" in p for p in s["props"])),
        sum(1 for s in sections if any("MEM_WRITE" in p for p in s["props"])),
    ]
    section_sizes = [(s["name"], s["size"]) for s in sections]
    section_entropy = [(s["name"], s["entropy"]) for s in sections]
    section_vsize = [(s["name"], s["vsize"]) for s in sections]
    entry_chars = [p for s in sections if s["name"] == entry for p in s["props"]]
    return np.hstack([
        np.asarray(general, dtype=np.float32),
        _hasher(50, section_sizes),
        _hasher(50, section_entropy),
        _hasher(50, section_vsize),
        _hasher_str(50, [entry]),
        _hasher_str(50, entry_chars),
    ]).astype(np.float32)


def _imports_info(b) -> np.ndarray:
    if b is None:
        return np.zeros(1280, dtype=np.float32)
    libraries: List[str] = []
    imports: List[str] = []
    try:
        for lib in b.imports:
            libraries.append(str(lib.name).lower())
            for entry in lib.entries:
                if getattr(entry, "is_ordinal", False):
                    imports.append(str(lib.name).lower() + ":ordinal" + str(entry.ordinal))
                else:
                    imports.append(str(lib.name).lower() + ":" + str(entry.name))
    except Exception:      # noqa: BLE001
        pass
    libraries = list(set(libraries))
    return np.hstack([
        _hasher_str(256, libraries),
        _hasher_str(1024, imports),
    ]).astype(np.float32)


def _exports_info(b) -> np.ndarray:
    if b is None:
        return np.zeros(128, dtype=np.float32)
    names: List[str] = []
    try:
        for e in list(b.exported_functions)[:10000]:
            names.append(getattr(e, "name", str(e)))
    except Exception:      # noqa: BLE001
        pass
    return _hasher_str(128, names)


def _data_directories(b) -> np.ndarray:
    out = np.zeros(30, dtype=np.float32)
    if b is None:
        return out
    try:
        dds = list(b.data_directories)[:15]
        for i, dd in enumerate(dds):
            out[2 * i] = float(dd.size)
            out[2 * i + 1] = float(getattr(dd, "rva", getattr(dd, "RVA", 0)))
    except Exception:      # noqa: BLE001
        pass
    return out


def extract_features(bytez: bytes) -> np.ndarray:
    """Return the full 2381-dim EMBER v2 feature vector for a PE byte string."""
    try:
        b = lief.PE.parse(list(bytez))
    except Exception:      # noqa: BLE001
        b = None

    vec = np.hstack([
        _byte_histogram(bytez),          # 256
        _byte_entropy_histogram(bytez),  # 256
        _string_features(bytez),         # 104
        _general_info(bytez, b),         # 10
        _header_info(b),                 # 62
        _section_info(b),                # 255
        _imports_info(b),                # 1280
        _exports_info(b),                # 128
        _data_directories(b),            # 30
    ]).astype(np.float32)
    return vec


FEATURE_DIM = 2381
