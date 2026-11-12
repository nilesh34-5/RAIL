"""Human-readable evidence report for a completed transfer.

`railcds.cli report` gathers, in one place, everything an auditor needs to see:
which objects were inspected and what happened to them, the Merkle root and
signature for each, the append-only audit chain and whether it verifies, the
ledger anchors written independently by both gateways, and the SHA-256 of every
file actually delivered on Network B.

It reads only artefacts on disk, so it can be run on either gateway at any time,
long after the transfer, and never needs the network.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .auditlog import AuditLog
from .config import Config


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _load(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def _hr(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def build_report(cfg: Config, out_dir: Optional[Path] = None,
                 spool_dir: Optional[Path] = None, full: bool = False) -> int:
    sender_log = cfg.resolve(cfg.audit["sender_log"])
    receiver_log = cfg.resolve(cfg.audit["receiver_log"])
    ledger_path = cfg.resolve(cfg.anchoring["ledger_path"])
    received = Path(out_dir) if out_dir else (cfg.root / "data" / "received")
    spool = Path(spool_dir) if spool_dir else (cfg.root / "data" / "spool")

    _hr("RAIL TRANSFER REPORT")
    print(f"policy id     : {cfg.policy_id}")
    print(f"risk bands B  : {cfg.integrity['risk_bands']}")
    print(f"generated     : {_fmt_ts(time.time())}")

    # ---------------- sender side -----------------------------------------
    s_entries = _load(sender_log)
    if s_entries:
        _hr("SENDER (Network A) - Stage S2/S3 decisions")
        print(f"log: {sender_log}   entries: {len(s_entries)}\n")
        print(f"{'object':<20} {'band':>4} {'event':<12} {'merkle root':<20} {'when'}")
        print("-" * 78)
        for e in s_entries:
            root = e.get("merkle_root", "") or "-"
            print(f"{str(e.get('object_name'))[:19]:<20} {e.get('band','-'):>4} "
                  f"{e.get('event','sent'):<12} {root[:18]:<20} "
                  f"{_fmt_ts(e.get('ts', 0))}")
        quarantined = [e for e in s_entries if e.get("event") == "quarantine"]
        if quarantined:
            print(f"\nQUARANTINED (never transmitted): "
                  f"{', '.join(str(e.get('object_name')) for e in quarantined)}")

    # ---------------- receiver side ---------------------------------------
    r_entries = _load(receiver_log)
    if r_entries:
        _hr("RECEIVER (Network B) - Stage S5 verification")
        print(f"log: {receiver_log}   entries: {len(r_entries)}\n")
        print(f"{'object':<20} {'band':>4} {'verified':>9} {'event':<14} "
              f"{'merkle root':<20}")
        print("-" * 78)
        for e in r_entries:
            print(f"{str(e.get('object_name'))[:19]:<20} {e.get('band','-'):>4} "
                  f"{str(e.get('verified')):>9} {e.get('event',''):<14} "
                  f"{str(e.get('merkle_root',''))[:18]:<20}")

    # ---------------- cross-check the two logs ----------------------------
    if s_entries and r_entries:
        _hr("CROSS-CHECK - do the two independent logs agree?")
        s_by_epoch = {e["epoch"]: e for e in s_entries if e.get("merkle_root")}
        matched = mismatched = 0
        for e in r_entries:
            se = s_by_epoch.get(e.get("epoch"))
            if not se:
                continue
            if se.get("merkle_root") == e.get("merkle_root"):
                matched += 1
                print(f"  MATCH    {str(e.get('object_name'))[:24]:<26} "
                      f"root {str(e.get('merkle_root'))[:24]}")
            else:
                mismatched += 1
                print(f"  MISMATCH {str(e.get('object_name'))[:24]:<26} "
                      f"sender={str(se.get('merkle_root'))[:16]} "
                      f"receiver={str(e.get('merkle_root'))[:16]}")
        print(f"\n  {matched} matching root(s), {mismatched} mismatch(es)")
        if mismatched == 0 and matched:
            print("  Both gateways independently committed to the same Merkle "
                  "roots.")

    # ---------------- audit chain integrity -------------------------------
    _hr("APPEND-ONLY AUDIT CHAIN INTEGRITY")
    for label, path in (("sender", sender_log), ("receiver", receiver_log)):
        if not path.exists():
            print(f"  {label:<9} (no log on this host)")
            continue
        broken = AuditLog(path, side=label).verify_chain()
        if broken is None:
            print(f"  {label:<9} CHAIN INTACT  ({len(_load(path))} entries)  {path}")
        else:
            print(f"  {label:<9} CHAIN BROKEN at entry index {broken}  {path}")

    # ---------------- ledger anchors --------------------------------------
    anchors = _load(ledger_path)
    _hr("LEDGER ANCHORS (Eq. 4 - risk-adaptive interval)")
    if not anchors:
        print(f"  none yet at {ledger_path}")
    else:
        print(f"  {'side':<10} {'band':>4}  {'epoch':<26} merkle root")
        print("  " + "-" * 74)
        for a in anchors:
            print(f"  {a.get('side','?'):<10} {a.get('band','-'):>4}  "
                  f"{str(a.get('epoch',''))[:24]:<26} "
                  f"{str(a.get('merkle_root',''))[:32]}")

    # ---------------- delivered files -------------------------------------
    _hr("DELIVERED OBJECTS ON NETWORK B")
    if not received.exists():
        print(f"  directory does not exist: {received}")
        print("  (nothing has been delivered yet - is the receiver running?)")
    else:
        files = [f for f in sorted(received.iterdir()) if f.is_file()]
        if not files:
            print(f"  {received} is empty - nothing delivered yet")
        else:
            print(f"  {received}\n")
            print(f"  {'file':<24} {'bytes':>9}  sha256")
            print("  " + "-" * 74)
            for f in files:
                data = f.read_bytes()
                print(f"  {f.name[:23]:<24} {len(data):>9}  "
                      f"{hashlib.sha256(data).hexdigest()}")

            # compare against the source spool when both are on this host
            if spool.exists():
                print("\n  Integrity vs the source objects:")
                for f in files:
                    src = spool / f.name
                    if not src.exists():
                        print(f"    {f.name:<24} (source not on this host)")
                        continue
                    a = hashlib.sha256(src.read_bytes()).hexdigest()
                    b = hashlib.sha256(f.read_bytes()).hexdigest()
                    print(f"    {f.name:<24} "
                          f"{'IDENTICAL' if a == b else 'DIFFERENT  <-- INVESTIGATE'}")

    _hr("END OF REPORT")
    return 0
