"""Download / provision the offline inspection models used by Stage S2.

    python scripts/download_models.py                 # YARA rules + EMBER2024 (if pkg)
    python scripts/download_models.py --yara-full      # also git-clone Yara-Rules
    python scripts/download_models.py --ember2024       # EMBER2024 LightGBM (HuggingFace)
    python scripts/download_models.py --ember2018-dataset  # 1.6 GB EMBER2018 tarball
    python scripts/download_models.py --deep            # MalConv + MalConvGCT (DL)

Offline ML / signature models wired into RAIL (see docs/MODELS.md):

  1. YARA signature rules  - offline pattern rules (yara-python).  A compact
     RAIL-authored rule set is always written locally; --yara-full additionally
     clones the community Yara-Rules corpus.
  2. EMBER2024 (thrember)  - pretrained LightGBM PE-malware classifiers hosted on
     HuggingFace; the recommended out-of-the-box supervised ML model.
  3. EMBER2018             - the classic 2381-feature LightGBM model; trained from
     the official dataset tarball (heavy) - instructions printed.
  4. MalConv / MalConvGCT  - pretrained deep raw-byte CNNs (PyTorch), --deep.
  5. ClamAV (optional)     - offline AV engine + signature DB via freshclam.

Everything downloaded here runs fully offline afterwards - no network calls are
made at inspection time.
"""
import argparse
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"

# A compact, self-contained YARA rule set that always compiles.
BUNDLED_YARA = r"""
rule EICAR_Test_File
{
    meta:
        description = "EICAR standard anti-malware test string"
        severity = "high"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Windows_PE_Executable
{
    meta:
        // Informational only: file typing is the file_type detector's job, so a
        // higher severity here would double-count the same evidence under the
        // Noisy-OR model, which assumes detectors are independent.
        description = "Windows PE executable marker (informational)"
        severity = "info"
    strings:
        $mz = "MZ"
        $dos = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $dos
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Encoded / obfuscated PowerShell often seen in droppers"
        severity = "medium"
    strings:
        $enc = "-enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $b64 = "FromBase64String" nocase
        $iex = "IEX(" nocase
    condition:
        2 of them
}

rule Script_In_Document
{
    meta:
        description = "Script tag or JS action embedded in a document object"
        severity = "medium"
    strings:
        $js1 = "/JavaScript"
        $js2 = "/OpenAction"
        $sh = "<script"
    condition:
        any of them
}

rule Embedded_Executable_Marker
{
    meta:
        description = "PE/ELF payload embedded inside a NON-executable carrier"
        severity = "medium"
    strings:
        $mz = "This program cannot be run in DOS mode"
        $elf = { 7F 45 4C 46 }
    condition:
        // Only fire when the carrier is not itself an executable. A normal PE
        // always contains the DOS stub string at ~offset 78, so testing merely
        // for its presence (or "not at 0") matches every legitimate binary.
        ($mz and uint16(0) != 0x5A4D)
        or ($elf in (64..filesize) and uint32(0) != 0x464C457F)
}
"""


def _write_bundled_yara() -> None:
    yd = MODELS / "yara"
    yd.mkdir(parents=True, exist_ok=True)
    (yd / "rail_bundled.yar").write_text(BUNDLED_YARA, encoding="utf-8")
    print(f"[+] wrote bundled YARA rules -> {yd / 'rail_bundled.yar'}")
    # validate they compile
    try:
        import yara
        yara.compile(source=BUNDLED_YARA)
        print("[+] bundled YARA rules compile OK")
    except Exception as exc:      # noqa: BLE001
        print(f"[!] YARA validation skipped/failed: {exc}")


def _clone_yara_full() -> None:
    if shutil.which("git") is None:
        print("[!] git not found; skipping --yara-full")
        return
    dst = MODELS / "yara" / "external"
    if dst.exists():
        print(f"[i] {dst} already present; skipping clone")
        return
    print("[i] cloning community Yara-Rules corpus (shallow)...")
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/Yara-Rules/rules", str(dst)],
        check=False,
    )
    print(f"[+] cloned Yara-Rules -> {dst} (unresolved-include files are skipped "
          f"at load time)")


EMBER2024_REPO = "joyce8/EMBER2024-benchmark-models"


def _download_ember2024(model_file: str = "EMBER2024_all.model") -> None:
    try:
        from huggingface_hub import hf_hub_download
    except Exception:      # noqa: BLE001
        print("[!] EMBER2024 needs 'thrember' (which pulls huggingface_hub). Install:")
        print("    pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")
        print("    pip install \"signify==0.5.2\"   # dependency pin for Python 3.13")
        return
    dst = MODELS / "ember2024"
    dst.mkdir(parents=True, exist_ok=True)
    print(f"[i] downloading EMBER2024 model '{model_file}' (~3.8 MB) -> {dst}")
    try:
        p = hf_hub_download(repo_id=EMBER2024_REPO, filename=model_file, local_dir=str(dst))
        print(f"[+] EMBER2024 model downloaded: {p}")
        # sanity-check it loads
        import lightgbm as lgb
        b = lgb.Booster(model_file=p)
        print(f"[+] model loads OK ({b.num_feature()} features)")
    except Exception as exc:      # noqa: BLE001
        print(f"[!] EMBER2024 download failed: {exc}")
        print("    Manual: python -c \"import thrember; thrember.download_models('models/ember2024')\"")


def _ember2018_instructions(do_download: bool) -> None:
    dst = MODELS / "ember"
    dst.mkdir(parents=True, exist_ok=True)
    tarball = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
    if do_download:
        out = dst / "ember_dataset_2018_2.tar.bz2"
        print(f"[i] downloading EMBER2018 dataset (~1.6 GB) -> {out}")
        try:
            urllib.request.urlretrieve(tarball, out)
            print(f"[+] downloaded {out}")
            print("    Next: extract, then train the model:")
        except Exception as exc:      # noqa: BLE001
            print(f"[!] download failed: {exc}")
    print("[i] EMBER2018 pretrained model (2381 features) is produced by training:")
    print(f"      pip install git+https://github.com/elastic/ember.git")
    print(f"      curl -O {tarball}")
    print(f"      tar xjf ember_dataset_2018_2.tar.bz2 -C {dst}")
    print(f"      python -c \"import ember; ember.create_vectorized_features(r'{dst}'); "
          f"ember.train_model(r'{dst}')\"")
    print(f"    -> place the resulting ember_model_2018.txt at "
          f"{dst / 'ember_model_2018.txt'}")


MALCONV_URL = ("https://github.com/pralab/secml_malware/raw/master/"
               "secml_malware/data/trained/pretrained_malconv.pth")
MALCONVGCT_URL = ("https://github.com/FutureComputing4AI/MalConv2/raw/main/"
                  "malconvGCT_nocat.checkpoint")


def _fetch(url: str, out: Path, label: str) -> bool:
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        print(f"[i] {label} already present ({out.stat().st_size/1e6:.1f} MB); skipping")
        return True
    print(f"[i] downloading {label} -> {out}")
    try:
        urllib.request.urlretrieve(url, out)
        print(f"[+] {label} downloaded ({out.stat().st_size/1e6:.1f} MB)")
        return True
    except Exception as exc:      # noqa: BLE001
        print(f"[!] {label} download failed: {exc}")
        return False


def _download_malconv(url: str | None = None) -> None:
    """Pretrained MalConv weights (secml_malware / PRALab)."""
    ok = _fetch(url or MALCONV_URL, MODELS / "malconv" / "pretrained_malconv.pth",
                "MalConv weights (~4 MB)")
    if ok:
        print("    enable with inspection.detectors.malconv_ml.enabled: true "
              "(requires: pip install torch)")


def _download_malconvgct(url: str | None = None) -> None:
    """Pretrained MalConvGCT checkpoint (FutureComputing4AI / Raff et al.)."""
    ok = _fetch(url or MALCONVGCT_URL,
                MODELS / "malconv" / "malconvGCT_nocat.checkpoint",
                "MalConvGCT checkpoint (~33 MB)")
    if ok:
        print("    enable with inspection.detectors.malconvgct_ml.enabled: true "
              "(requires: pip install torch)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yara", dest="yara", action="store_true", default=True)
    ap.add_argument("--no-yara", dest="yara", action="store_false")
    ap.add_argument("--yara-full", action="store_true")
    ap.add_argument("--ember2024", action="store_true", default=None)
    ap.add_argument("--ember2018-dataset", action="store_true")
    ap.add_argument("--malconv", nargs="?", const=True, default=None,
                    metavar="URL", help="download pretrained MalConv weights")
    ap.add_argument("--malconvgct", nargs="?", const=True, default=None,
                    metavar="URL", help="download pretrained MalConvGCT checkpoint")
    ap.add_argument("--deep", action="store_true",
                    help="download both deep-learning models (MalConv + MalConvGCT)")
    args = ap.parse_args()

    MODELS.mkdir(parents=True, exist_ok=True)
    print("=" * 68)
    print("RAIL offline inspection model provisioning")
    print("=" * 68)

    if args.yara:
        _write_bundled_yara()
    if args.yara_full:
        _clone_yara_full()

    # EMBER2024 auto-attempted if thrember is importable, unless explicitly off
    if args.ember2024 or (args.ember2024 is None):
        _download_ember2024()

    _ember2018_instructions(args.ember2018_dataset)

    if args.malconv or args.deep:
        _download_malconv(args.malconv if isinstance(args.malconv, str) else None)
    if args.malconvgct or args.deep:
        _download_malconvgct(args.malconvgct if isinstance(args.malconvgct, str) else None)

    print("-" * 68)
    print("Done. Verify what loaded with:  python -m railcds.cli detectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
