"""End-to-end RAIL demonstration in a single process (no sockets required).

    python scripts/demo_local.py [--loss 0.2] [--spool data/spool]

Runs the full S1->S6 pipeline for every object in the spool directory, passing
the FEC symbols through a simulated lossy one-way channel, and prints how the
risk score drives chunk size and anchoring while the receiver independently
verifies and delivers each object.  Demonstrates:
  * risk-adaptive chunking  (higher risk -> smaller chunks)
  * blocking of high-risk objects (quarantine)
  * FEC recovery under packet loss (no back channel)
  * independent sender/receiver audit logs and ledger anchoring
"""
import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import warnings                                      # noqa: E402
warnings.simplefilter("ignore")

from railcds.config import load_config              # noqa: E402
from railcds.models import TransferObject           # noqa: E402
from railcds.protocol_break import ProtocolBreak    # noqa: E402
from railcds.sender import SenderGateway            # noqa: E402
from railcds.receiver import ReceiverGateway        # noqa: E402


class CaptureSender:
    """Stands in for UdpSender: collects datagrams instead of transmitting."""
    def __init__(self):
        self.datagrams = []
    def send(self, dg): self.datagrams.append(dg)
    def send_many(self, dgs):
        n = 0
        for d in dgs:
            self.datagrams.append(d); n += 1
        return n
    def close(self): pass


class DummyReceiver:
    def close(self): pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--loss", type=float, default=0.15, help="datagram loss rate")
    ap.add_argument("--spool", default="data/spool")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    random.seed(1)

    cfg = load_config(args.config)
    cap = CaptureSender()
    tx = SenderGateway(cfg, sender=cap)
    results = []
    rx = ReceiverGateway(cfg, out_dir=cfg.root / "data" / "received",
                         receiver=DummyReceiver(), on_result=results.append)

    objs = list(ProtocolBreak(spool_dir=Path(args.spool)).iter_spool())
    if not objs:
        print(f"[!] no objects in {args.spool}; run scripts/make_test_object.py")
        return 2

    print(f"FEC backend: {tx.fec.effective_backend}   simulated loss: {args.loss:.0%}")
    print("=" * 92)
    hdr = f"{'object':16} {'risk':>6} {'band':>4} {'chunk_sz':>9} {'chunks':>7} " \
          f"{'symbols':>8} {'sent':>6} {'status':>10} {'anchor(s)':>10}"
    print(hdr); print("-" * 92)

    for obj in objs:
        cap.datagrams.clear()
        s = tx.process(obj)
        if s["status"] == "QUARANTINED":
            print(f"{obj.name:16} {s['risk']:6.3f} {s['band']:>4} "
                  f"{'-':>9} {'-':>7} {'-':>8} {'-':>6} {'QUARANTINE':>10} {'-':>10}")
            continue
        # simulated lossy one-way channel
        survived = [d for d in cap.datagrams if random.random() > args.loss]
        random.shuffle(survived)
        before = len(results)
        for d in survived:
            rx._handle_datagram(d)
        delivered = results[before:]
        status = delivered[0]["status"] if delivered else "LOST"
        print(f"{obj.name:16} {s['risk']:6.3f} {s['band']:>4} "
              f"{s['chunk_size']:>9} {s['chunk_count']:>7} {s['symbols_sent']:>8} "
              f"{len(survived):>6} {status:>10} {s['anchor_interval_s']:>10.1f}")

    print("=" * 92)
    verified = sum(1 for r in results if r.get("verified"))
    print(f"delivered & verified on Network B: {verified}/{len(objs)} "
          f"(quarantined objects never left Network A)")
    print(f"sender audit log:   {cfg.resolve(cfg.audit['sender_log'])}")
    print(f"receiver audit log: {cfg.resolve(cfg.audit['receiver_log'])}")
    print(f"ledger anchors:     {cfg.resolve(cfg.anchoring['ledger_path'])}")
    print("verify a log's integrity with:  python -m railcds.cli verify-log <path>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
