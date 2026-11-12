"""Package RAIL into copy-ready SENDER / RECEIVER / DOCS folders.

    python scripts/package_dist.py [--out dist] [--sender-ip A] [--receiver-ip B]

Produces:

    dist/SENDER/     copy to Network A - full stack: inspection, ML models,
                     private key, spool, all tooling
    dist/RECEIVER/   copy to Network B - minimal: no inspection code, no ML
                     models, public key only
    dist/DOCS/       every guide, kept out of both gateways so you can read
                     them while testing

The receiver does not import the inspection package, so shipping it there
would only enlarge the trusted computing base on the side the architecture is
protecting.
"""
import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

# --------------------------------------------------------------------------
SENDER_SCRIPTS = [
    "download_models.py", "train_anomaly.py", "gen_keys.py",
    "make_test_object.py", "demo_local.py", "demo_attacks.py",
    "evaluate.py", "benchmark_models.py", "package_dist.py",
]
RECEIVER_SCRIPTS: list[str] = []          # the receiver needs no tooling
# the receiver must not carry the inspection package or the sender gateway
RECEIVER_EXCLUDE = {"inspection", "sender.py"}
TEMPLATES = ROOT / "scripts" / "dist_templates"
DOCS = ["ARCHITECTURE.md", "MODELS.md", "RUNBOOK.md", "RESULTS.md",
        "TESTING_GUIDE.md", "NETWORK_HARDENING.md", "FINAL_TEST_REPORT.md",
        "KALI_TWO_VM_TEST.md"]




def normalise_shell_endings(root: Path) -> int:
    """Force LF on every shipped .sh file.

    Editing these from Windows can rewrite them with CRLF, and bash on
    Linux then fails with "set: pipefail: invalid option name".
    """
    crlf, lf = bytes([13, 10]), bytes([10])
    n = 0
    for f in root.rglob("*.sh"):
        data = f.read_bytes()
        if crlf in data:
            f.write_bytes(data.replace(crlf, lf))
            n += 1
    return n

def write_template(name: str, dst: Path, sender_ip: str, receiver_ip: str) -> None:
    """Copy a dist_templates file, substituting the peer addresses."""
    src = TEMPLATES / name
    if not src.exists():
        return
    text = (src.read_text(encoding="utf-8")
               .replace("__SENDER_IP__", sender_ip)
               .replace("__RECEIVER_IP__", receiver_ip))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")


def copy_package(dst: Path, exclude: set[str]) -> None:
    src = ROOT / "railcds"
    for item in sorted(src.iterdir()):
        if item.name in exclude or item.name == "__pycache__":
            continue
        target = dst / "railcds" / item.name
        if item.is_dir():
            shutil.copytree(item, target,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def write_config(dst: Path, role: str, sender_ip: str, receiver_ip: str) -> None:
    cfg = yaml.safe_load((ROOT / "config" / "rail.yaml").read_text(encoding="utf-8"))
    cfg["transport"]["send_host"] = receiver_ip
    cfg["transport"]["bind_host"] = "0.0.0.0"
    if role == "receiver":
        # the receiver never signs and never inspects; drop what it cannot use
        cfg.pop("inspection", None)
        cfg["crypto"].pop("sender_private_key", None)
        cfg["integrity"].pop("chunk_max_bytes", None)
        cfg["integrity"].pop("chunk_min_bytes", None)
        cfg.pop("fec", None)
    out = dst / "config"
    out.mkdir(parents=True, exist_ok=True)
    header = (f"# RAIL {role.upper()} configuration\n"
              f"# sender (Network A) = {sender_ip}\n"
              f"# receiver (Network B) = {receiver_ip}\n"
              f"# policy.id and integrity.risk_bands MUST match the other side.\n")
    (out / "rail.yaml").write_text(
        header + yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")


def build_sender(dist: Path, sender_ip: str, receiver_ip: str) -> None:
    d = dist / "SENDER"
    copy_package(d, exclude=set())
    write_config(d, "sender", sender_ip, receiver_ip)

    (d / "scripts").mkdir(parents=True, exist_ok=True)
    for s in SENDER_SCRIPTS:
        if (ROOT / "scripts" / s).exists():
            shutil.copy2(ROOT / "scripts" / s, d / "scripts" / s)

    # models: everything the inspection stage needs
    if (ROOT / "models").exists():
        shutil.copytree(ROOT / "models", d / "models",
                        ignore=shutil.ignore_patterns(".cache", "__pycache__"),
                        dirs_exist_ok=True)

    # tests travel with the sender - it is the full install
    shutil.copytree(ROOT / "tests", d / "tests",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                    dirs_exist_ok=True)

    # keys: private stays here
    kd = d / "data" / "keys"
    kd.mkdir(parents=True, exist_ok=True)
    for k in ("sender_ed25519.key", "sender_ed25519.pub"):
        src = ROOT / "data" / "keys" / k
        if src.exists():
            shutil.copy2(src, kd / k)

    sd = d / "data" / "spool"
    sd.mkdir(parents=True, exist_ok=True)
    for f in (ROOT / "data" / "spool").glob("*"):
        if f.is_file() and not f.name.startswith("."):
            shutil.copy2(f, sd / f.name)

    shutil.copy2(ROOT / "requirements.txt", d / "requirements.txt")
    write_template("SENDER_START_HERE.md", d / "START_HERE.md",
                   sender_ip, receiver_ip)
    write_template("setup_kali_sender.sh", d / "setup_kali_sender.sh",
                   sender_ip, receiver_ip)


def build_receiver(dist: Path, sender_ip: str, receiver_ip: str) -> None:
    d = dist / "RECEIVER"
    copy_package(d, exclude=RECEIVER_EXCLUDE)
    write_config(d, "receiver", sender_ip, receiver_ip)

    kd = d / "data" / "keys"
    kd.mkdir(parents=True, exist_ok=True)
    pub = ROOT / "data" / "keys" / "sender_ed25519.pub"
    if pub.exists():
        shutil.copy2(pub, kd / "sender_ed25519.pub")   # PUBLIC key only
    (d / "data" / "received").mkdir(parents=True, exist_ok=True)

    (d / "requirements.txt").write_text(
        "# RAIL RECEIVER - minimal dependency set.\n"
        "# The receiver performs no inspection, so it needs no ML stack:\n"
        "# no lightgbm, no torch, no yara, no lief.\n"
        "cryptography>=42.0\n"
        "PyYAML>=6.0\n"
        "numpy>=1.24\n", encoding="utf-8")
    write_template("RECEIVER_START_HERE.md", d / "START_HERE.md",
                   sender_ip, receiver_ip)
    write_template("setup_kali_receiver.sh", d / "setup_kali_receiver.sh",
                   sender_ip, receiver_ip)


def build_docs(dist: Path, sender_ip: str, receiver_ip: str) -> None:
    d = dist / "DOCS"
    d.mkdir(parents=True, exist_ok=True)
    for name in DOCS:
        src = ROOT / "docs" / name
        if src.exists():
            shutil.copy2(src, d / name)
    for extra in ("README.md",):
        if (ROOT / extra).exists():
            shutil.copy2(ROOT / extra, d / f"OVERVIEW_{extra}")
    # deployment collateral belongs with the docs, not inside a gateway
    if (ROOT / "deploy").exists():
        shutil.copytree(
            ROOT / "deploy", d / "deploy",
            # .vagrant/ is per-machine VM state and the logs are from local test
            # runs; neither belongs in a distributable package.
            ignore=shutil.ignore_patterns("__pycache__", ".vagrant",
                                          "*.log", "*.box"),
            dirs_exist_ok=True)
    if (ROOT / "results_evaluation.json").exists():
        shutil.copy2(ROOT / "results_evaluation.json",
                     d / "results_evaluation.json")
    write_template("DOCS_INDEX.md", d / "INDEX.md", sender_ip, receiver_ip)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist")
    ap.add_argument("--sender-ip", default="10.20.0.10")
    ap.add_argument("--receiver-ip", default="10.20.0.20")
    args = ap.parse_args()

    dist = Path(args.out)
    if not dist.is_absolute():
        dist = ROOT / dist
    if dist.exists():
        shutil.rmtree(dist)
    dist.mkdir(parents=True)

    build_sender(dist, args.sender_ip, args.receiver_ip)
    build_receiver(dist, args.sender_ip, args.receiver_ip)
    build_docs(dist, args.sender_ip, args.receiver_ip)
    write_template("DIST_README.md", dist / "README.md",
                   args.sender_ip, args.receiver_ip)
    fixed = normalise_shell_endings(dist)
    if fixed:
        print(f"    normalised {fixed} shell script(s) to LF endings")

    print(f"[+] packaged into {dist}")
    for sub in ("SENDER", "RECEIVER", "DOCS"):
        p = dist / sub
        n = sum(1 for _ in p.rglob("*") if _.is_file())
        size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
        print(f"    {sub:9} {n:4d} files  {size/1e6:7.1f} MB")
    print("\n    copy SENDER/ to Network A, RECEIVER/ to Network B,"
          "\n    and keep DOCS/ open while you test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
