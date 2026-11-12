"""Create sample objects that exercise different points of the risk scale.

    python scripts/make_test_object.py [--out data/spool]

Produces, in the spool directory:
  * benign.txt        - ordinary text                       (low risk)
  * report.pdf        - a minimal well-formed PDF            (low risk)
  * random.bin        - high-entropy random bytes            (raises anomaly)
  * signature_hit.txt - contains the EICAR *marker string*   (YARA hit)
  * suspicious.ps1    - encoded-PowerShell markers           (YARA hit)
  * polyglot.pdf      - a PDF that is also a valid ZIP and carries a PE header
                        (polyglot -> high risk; the Koch et al. threat)

None of these are real malware.  We do NOT write the functional
EICAR file, because host antivirus (e.g. Windows Defender) would quarantine it
before RAIL sees it; instead signature_hit.txt embeds only the harmless EICAR
*marker substring* so the bundled YARA rule fires.  To exercise RAIL against
real malware, do so inside an isolated VM with host AV disabled (see
deploy/README_NETWORK.md).
"""
import argparse
import os
from pathlib import Path

# NOT the functional EICAR file - only the harmless identifying marker substring
EICAR_MARKER = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

SUSPICIOUS_PS1 = (
    "powershell -nop -w hidden -enc "
    "JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n"
    "$data = [System.Convert]::FromBase64String($blob)\n"
    "IEX([System.Text.Encoding]::UTF8.GetString($data))\n"
)

MINIMAL_PDF = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj
xref
0 4
0000000000 65535 f
trailer<</Root 1 0 R/Size 4>>
startxref
149
%%EOF
"""

# A real MZ header followed by the standard DOS stub message.  Embedding this in
# a PDF makes the object valid as more than one type, which is what
# the file_type polyglot detector and the Embedded_Executable_Marker YARA rule
# are meant to catch.
PE_STUB = (
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    + b"\x00" * 48
    + b"This program cannot be run in DOS mode.\r\r\n$\x00"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/spool")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    (out / "benign.txt").write_text(
        "RAIL cross-domain transfer test object.\n" * 64, encoding="utf-8")
    (out / "report.pdf").write_bytes(MINIMAL_PDF)
    (out / "random.bin").write_bytes(os.urandom(64 * 1024))
    (out / "signature_hit.txt").write_text(
        "Quarterly status note.\n"
        "Reference test token: " + EICAR_MARKER + "\n"
        "End of note.\n", encoding="ascii")
    (out / "suspicious.ps1").write_text(SUSPICIOUS_PS1, encoding="ascii")

    # polyglot: PDF header, an embedded ZIP local header, and a real PE stub
    poly = bytearray(MINIMAL_PDF)
    poly += b"\nPK\x03\x04embedded-zip-part\nPK\x05\x06" + b"\x00" * 18
    poly += b"\n" + PE_STUB + b"\n"
    (out / "polyglot.pdf").write_bytes(bytes(poly))

    print(f"[+] wrote sample objects to {out.resolve()}")
    for p in sorted(out.iterdir()):
        if p.is_file() and not p.name.startswith("."):
            print(f"    {p.name:<18} {p.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
