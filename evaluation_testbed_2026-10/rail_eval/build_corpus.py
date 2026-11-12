"""Build the benign evaluation corpus.

Govdocs1 and the EMBER2024 test split could not be downloaded from the test
environment, so the benign corpus is assembled from software that is benign by
construction and publicly traceable:

  pe        Windows PE files (.pyd/.dll/.exe) unpacked from official PyPI
            win_amd64 wheels (numpy, scipy, pandas, pywin32, ...) + launchers
  elf       Linux ELF executables and shared objects from the Ubuntu base image
  pdf       PDF documents shipped with Ubuntu / Python packages
  office    OOXML documents (.docx/.pptx/.xlsx/.xls) from the python-docx,
            python-pptx, openpyxl and xlrd source distributions
  image     PNG / JPEG / GIF images from the base image
  text      plain text, Markdown, HTML, XML, JSON, CSV, Python, JS, SVG
  archive   ZIP and gzip archives from the base image

Sampling is stratified and seeded, files are de-duplicated by SHA-256 and
capped at 20 MiB.  A manifest (CSV) records class, size, sha256 and origin.

    python build_corpus.py --out /opt/dl/corpus/benign
"""
import argparse
import csv
import hashlib
import os
import random
import shutil
import zipfile
from pathlib import Path

SEED = 2026
MAXB = 20 * 1024 * 1024
MINB = 512

QUOTA = {"pe": 300, "elf": 150, "pdf": 200, "office": 120, "image": 120,
         "text": 225, "archive": 40}
TEXT_EXT = ["txt", "md", "html", "xml", "json", "csv", "py", "js", "svg"]
SCAN_ROOTS = ["/usr", "/opt/venvA/lib", "/opt/dl/sdists"]


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def walk(roots, pred):
    out = []
    for r in roots:
        for dp, dn, fn in os.walk(r):
            if "/proc" in dp:
                continue
            for f in fn:
                p = Path(dp) / f
                try:
                    if p.is_symlink() or not p.is_file():
                        continue
                    sz = p.stat().st_size
                except OSError:
                    continue
                if MINB <= sz <= MAXB and pred(p):
                    out.append(p)
    return sorted(out)


def is_elf(p):
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/opt/dl/corpus/benign")
    ap.add_argument("--wheels", default="/opt/dl/wheels_win")
    a = ap.parse_args()
    rng = random.Random(SEED)
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    staging = Path("/opt/dl/pe_extract")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    # ---- PE from Windows wheels -------------------------------------------
    pe = []
    for whl in sorted(Path(a.wheels).glob("*.whl")):
        with zipfile.ZipFile(whl) as z:
            for info in z.infolist():
                n = info.filename.lower()
                if n.endswith((".pyd", ".dll", ".exe")) and MINB <= info.file_size <= MAXB:
                    dst = staging / whl.stem / info.filename
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info) as src, open(dst, "wb") as d:
                        shutil.copyfileobj(src, d)
                    with open(dst, "rb") as f:
                        if f.read(2) == b"MZ":
                            pe.append((dst, f"pypi:{whl.name}"))

    pools = {"pe": pe}
    elf_roots = ["/usr/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu"]
    pools["elf"] = [(p, "ubuntu") for p in walk(elf_roots, is_elf)]
    pools["pdf"] = [(p, "ubuntu/pypi") for p in walk(SCAN_ROOTS, lambda p: p.suffix.lower() == ".pdf")]
    pools["office"] = [(p, "pypi-sdist") for p in walk(["/opt/dl/sdists"], lambda p: p.suffix.lower() in (".docx", ".pptx", ".xlsx", ".xls", ".odt"))]
    pools["image"] = [(p, "ubuntu/pypi") for p in walk(SCAN_ROOTS, lambda p: p.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif"))]
    pools["archive"] = [(p, "ubuntu/pypi") for p in walk(SCAN_ROOTS, lambda p: p.suffix.lower() in (".zip", ".gz"))]
    text = []
    per_ext = QUOTA["text"] // len(TEXT_EXT)
    for ext in TEXT_EXT:
        cand = walk(SCAN_ROOTS, lambda p, e=ext: p.suffix.lower() == "." + e)
        rng.shuffle(cand)
        text += [(p, "ubuntu/pypi") for p in cand[:per_ext * 3]]
    pools["text"] = text

    rows, seen = [], set()
    for cls, pool in pools.items():
        pool = list(pool)
        rng.shuffle(pool)
        if cls == "image":       # keep the image mix balanced across formats
            pool.sort(key=lambda t: t[0].suffix.lower() in (".png",))
        if cls == "text":        # take an equal share of each text extension
            by = {}
            for p, o in pool:
                by.setdefault(p.suffix.lower(), []).append((p, o))
            from itertools import zip_longest
            pool = [x for grp in zip_longest(*by.values()) for x in grp if x is not None]
        n = 0
        d = out / cls
        d.mkdir()
        for p, origin in pool:
            if n >= QUOTA[cls]:
                break
            h = sha(p)
            if h in seen:
                continue
            seen.add(h)
            n += 1
            name = f"{cls}_{n:04d}{p.suffix.lower() if p.suffix else ''}"
            shutil.copyfile(p, d / name)
            rows.append({"file": f"{cls}/{name}", "class": cls, "size": p.stat().st_size,
                         "sha256": h, "origin": origin, "source_name": p.name})
        print(f"{cls:8s} pool={len(pool):6d} taken={n}")
    with open(out / "manifest.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"total {len(rows)} files -> {out}")


if __name__ == "__main__":
    main()
