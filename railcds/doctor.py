"""Pre-flight health check for a RAIL gateway.

    python -m railcds.cli doctor --role sender   --peer 10.0.2.9
    python -m railcds.cli doctor --role receiver --peer 10.0.2.8

Verifies, in one pass, everything that must be true before a transfer:
the Python environment, every dependency, the offline ML models, key material,
the configuration, the inspection detectors, network reachability and whether
OS-level enforcement is active.

Each line is PASS, WARN or FAIL. WARN means degraded but workable; FAIL means
the transfer will not succeed until it is fixed. The exit code is non-zero if
anything FAILed, so this can gate a scripted run.
"""
from __future__ import annotations

import importlib
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"

# packages both sides need, then the sender-only inspection stack
CORE_PKGS = [("cryptography", "cryptography"), ("yaml", "PyYAML"),
             ("numpy", "numpy")]
SENDER_PKGS = [("sklearn", "scikit-learn"), ("joblib", "joblib"),
               ("lightgbm", "lightgbm"), ("yara", "yara-python"),
               ("magic", "python-magic"), ("lief", "lief"),
               ("torch", "torch"), ("thrember", "thrember")]
# (path, label, required?)
SENDER_MODELS = [
    ("models/ember2024/EMBER2024_all.model", "EMBER2024 classifier", False),
    ("models/malconv/pretrained_malconv.pth", "MalConv weights", False),
    ("models/malconv/malconvGCT_nocat.checkpoint", "MalConvGCT checkpoint", False),
    ("models/yara/rail_bundled.yar", "YARA rules", True),
    ("models/anomaly_isoforest.joblib", "anomaly model", False),
]


class Check:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, str, str]] = []

    def add(self, status: str, item: str, detail: str = "") -> None:
        self.rows.append((status, item, detail))

    def section(self, title: str) -> None:
        self.rows.append(("", f"__SECTION__{title}", ""))

    @property
    def failures(self) -> int:
        return sum(1 for s, _, _ in self.rows if s == FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for s, _, _ in self.rows if s == WARN)

    def render(self) -> None:
        for status, item, detail in self.rows:
            if item.startswith("__SECTION__"):
                print(f"\n{item[11:]}")
                print("-" * 78)
                continue
            print(f"  [{status}] {item:<34} {detail}")


def _ping(host: str, timeout: int = 2) -> bool:
    flag = "-n" if platform.system() == "Windows" else "-c"
    wait = "-w" if platform.system() == "Windows" else "-W"
    try:
        r = subprocess.run(["ping", flag, "1", wait, str(timeout), host],
                           capture_output=True, timeout=timeout + 4)
        return r.returncode == 0
    except Exception:      # noqa: BLE001
        return False


def _port_free(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((host if host != "0.0.0.0" else "", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def run(cfg, role: str, peer: Optional[str]) -> int:
    c = Check()
    root = cfg.root
    is_sender = role == "sender"

    # ---------------- environment ----------------------------------------
    c.section("1. ENVIRONMENT")
    c.add(PASS, "python version", platform.python_version())
    in_venv = sys.prefix != sys.base_prefix
    c.add(PASS if in_venv else FAIL, "virtualenv active",
          sys.prefix if in_venv else "NOT in a venv - run: source .venv/bin/activate")
    c.add(PASS, "platform", f"{platform.system()} {platform.release()}")
    c.add(PASS if (root / "railcds").is_dir() else FAIL, "project root", str(root))

    # ---------------- packages -------------------------------------------
    c.section("2. PYTHON PACKAGES")
    for mod, name in CORE_PKGS:
        try:
            m = importlib.import_module(mod)
            c.add(PASS, name, getattr(m, "__version__", "ok"))
        except Exception as exc:      # noqa: BLE001
            c.add(FAIL, name, f"MISSING - {type(exc).__name__}")
    if is_sender:
        for mod, name in SENDER_PKGS:
            try:
                m = importlib.import_module(mod)
                c.add(PASS, name, getattr(m, "__version__", "ok"))
            except Exception:      # noqa: BLE001
                c.add(WARN, name, "missing - the matching detector is skipped")

    # ---------------- FEC -------------------------------------------------
    c.section("3. FORWARD ERROR CORRECTION")
    try:
        from .fec import FEC, _have_raptorq
        backend = FEC(backend=cfg.fec["backend"] if "fec" in cfg.raw else "auto"
                      ).effective_backend if "fec" in cfg.raw else \
            FEC(backend="auto").effective_backend
        c.add(PASS, "raptorq available", str(_have_raptorq()))
        c.add(PASS, "effective backend", backend)
        c.add(WARN, "MUST MATCH THE OTHER SIDE",
              f"the peer must also report '{backend}'")
    except Exception as exc:      # noqa: BLE001
        c.add(FAIL, "FEC layer", f"{type(exc).__name__}: {exc}")

    # ---------------- models ---------------------------------------------
    if is_sender:
        c.section("4. OFFLINE ML / SIGNATURE MODELS")
        for rel, label, required in SENDER_MODELS:
            p = root / rel
            if p.exists():
                c.add(PASS, label, f"{p.stat().st_size/1e6:.1f} MB  {rel}")
            else:
                c.add(FAIL if required else WARN, label,
                      f"missing: {rel}  (run scripts/download_models.py --deep)")

    # ---------------- keys ------------------------------------------------
    c.section("5. KEY MATERIAL")
    priv = root / "data" / "keys" / "sender_ed25519.key"
    pub = root / "data" / "keys" / "sender_ed25519.pub"
    c.add(PASS if pub.exists() else FAIL, "public key",
          str(pub) if pub.exists() else "MISSING - copy it from the sender")
    if is_sender:
        c.add(PASS if priv.exists() else FAIL, "private key",
              "present (correct on the sender)" if priv.exists()
              else "MISSING - run scripts/gen_keys.py")
    else:
        c.add(PASS if not priv.exists() else FAIL, "private key absent",
              "correct - the receiver must never hold it" if not priv.exists()
              else "PRESENT ON THE RECEIVER - delete it: rm data/keys/sender_ed25519.key")

    # ---------------- configuration ---------------------------------------
    c.section("6. CONFIGURATION")
    t = cfg.transport
    c.add(PASS, "policy id", f"{cfg.policy_id}   (must match the peer)")
    c.add(PASS, "risk bands B", f"{cfg.integrity['risk_bands']}   (must match the peer)")
    if is_sender:
        target = t.get("send_host")
        ok = bool(peer is None or target == peer)
        c.add(PASS if ok else FAIL, "send_host",
              f"{target}:{t.get('send_port')}"
              + ("" if ok else f"   EXPECTED {peer} - fix config/rail.yaml"))
        # A send_host pointing at this machine is a classic mis-set: the sender
        # transmits to itself and nothing ever reaches Network B.
        self_send = target in _local_ips()
        c.add(FAIL if self_send else PASS, "self-send guard",
              "send_host is THIS machine - fix it" if self_send
              else "send_host is not a local address")
    else:
        c.add(PASS, "bind", f"{t.get('bind_host')}:{t.get('bind_port')}")
        free = _port_free(str(t.get("bind_host")), int(t.get("bind_port")))
        c.add(PASS if free else WARN, "listening port",
              "free" if free else "already in use - a receiver may be running")

    # ---------------- detectors -------------------------------------------
    if is_sender:
        c.section("7. INSPECTION DETECTORS (Stage S2)")
        try:
            from .inspection.engine import InspectionEngine
            eng = InspectionEngine(cfg)
            avail = [d for d in eng.detectors if d.available]
            for d in eng.detectors:
                c.add(PASS if d.available else WARN, d.name,
                      f"weight={d.weight}" if d.available
                      else f"UNAVAILABLE - {d._load_error[:44]}")
            c.add(PASS if len(avail) >= 4 else FAIL, "detectors available",
                  f"{len(avail)} of {len(eng.detectors)}")
            c.add(PASS, "block threshold", str(eng.block_threshold))
            if len(avail) < len(eng.detectors):
                c.add(WARN, "reduced inspection",
                      "risk scores will be LOWER; some objects that should be "
                      "quarantined may pass")
        except Exception as exc:      # noqa: BLE001
            c.add(FAIL, "inspection engine", f"{type(exc).__name__}: {exc}")

    # ---------------- directories -----------------------------------------
    c.section("8. DIRECTORIES")
    if is_sender:
        spool = root / "data" / "spool"
        n = len([f for f in spool.glob("*")
                 if f.is_file() and not f.name.startswith(".")]) if spool.exists() else 0
        c.add(PASS if n else WARN, "spool (objects to send)",
              f"{n} object(s) in {spool}" if n
              else f"empty - run scripts/make_test_object.py")
    else:
        rec = root / "data" / "received"
        c.add(PASS, "received (delivered objects)",
              f"{str(rec)}  ({'exists' if rec.exists() else 'will be created'})")

    # ---------------- network ---------------------------------------------
    c.section("9. NETWORK")
    if peer:
        reachable = _ping(peer)
        c.add(PASS if reachable else WARN, f"peer {peer} reachable",
              "yes" if reachable
              else "no - EXPECTED if the lock is applied; otherwise fix the adapter")
        if is_sender and platform.system() != "Windows":
            try:
                r = subprocess.run(["ip", "neigh", "show", peer],
                                   capture_output=True, text=True)
                out = r.stdout.strip()
                if "PERMANENT" in out:
                    c.add(PASS, "static ARP entry", out)
                elif out:
                    c.add(WARN, "static ARP entry",
                          "learnt but NOT permanent - pin it before a total lock")
                else:
                    c.add(WARN, "static ARP entry",
                          "none - required before locking the receiver")
            except Exception:      # noqa: BLE001
                pass
    else:
        c.add(WARN, "peer", "not given - pass --peer <ip> for network checks")

    # ---------------- enforcement -----------------------------------------
    c.section("10. OS-LEVEL ENFORCEMENT")
    try:
        from . import netenforce
        active, msg = netenforce.status(peer or "")
        c.add(PASS if active else WARN, "lockdown", msg)
        if not active:
            other = "10.0.2.9" if is_sender else "10.0.2.8"
            c.add(WARN, "to enforce",
                  f"lockdown --role {role} --peer {peer or other} "
                  f"--scope total --apply")
    except Exception as exc:      # noqa: BLE001
        c.add(WARN, "lockdown", f"could not determine: {exc}")

    # ---------------- render ----------------------------------------------
    print("=" * 78)
    print(f"RAIL DOCTOR - role={role}" + (f"  peer={peer}" if peer else ""))
    print("=" * 78)
    c.render()
    print("\n" + "=" * 78)
    if c.failures:
        print(f"RESULT: {c.failures} FAILURE(S), {c.warnings} warning(s) "
              f"- fix the FAILs before transferring")
    else:
        print(f"RESULT: READY  ({c.warnings} warning(s))")
    print("=" * 78)
    return 1 if c.failures else 0


def _local_ips() -> List[str]:
    ips = ["127.0.0.1", "0.0.0.0"]
    try:
        host = socket.gethostname()
        ips.append(socket.gethostbyname(host))
        for info in socket.getaddrinfo(host, None):
            ips.append(info[4][0])
    except Exception:      # noqa: BLE001
        pass
    return ips
