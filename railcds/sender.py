"""Sender-side gateway (Network A): Stages S1 -> S4 plus the audit path.

Orchestrates, per object:
    S1  protocol separation (object already extracted by ProtocolBreak)
    S2  layered inspection -> risk r, block check, quantised band r_tilde
    S3  adaptive chunking c(r_tilde), linked hash chain, Merkle root, signature,
        append-only audit log, risk-adaptive ledger anchoring T(r_tilde)
    S4  FEC encoding + transmission over the one-way link
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import wire
from .anchoring import AnchorManager, Ledger
from .auditlog import AuditLog
from .chunker import chunk_object, chunk_size_for_risk
from .config import Config
from .crypto import Signer
from .fec import make_fec
from .hashchain import build_hash_chain
from .inspection.engine import InspectionEngine
from .merkle import merkle_root
from .models import Manifest, TransferObject
from .session import Session
from .transport import UdpSender


class SenderGateway:
    def __init__(self, cfg: Config, sender: Optional[UdpSender] = None) -> None:
        self.cfg = cfg
        self.engine = InspectionEngine(cfg)
        self.signer = Signer.from_file(cfg.resolve(cfg.crypto["sender_private_key"]))
        self.fec = make_fec(cfg.fec)
        self.c_max = int(cfg.integrity["chunk_max_bytes"])
        self.c_min = int(cfg.integrity["chunk_min_bytes"])
        self.policy_id = cfg.policy_id

        ledger = Ledger(
            backend=cfg.anchoring["backend"],
            path=cfg.resolve(cfg.anchoring["ledger_path"]),
            endpoint=cfg.anchoring.get("endpoint"),
        )
        self.anchor = AnchorManager(cfg.anchoring, ledger)
        self.audit = AuditLog(cfg.resolve(cfg.audit["sender_log"]), side="sender")

        t = cfg.transport
        self.sender = sender or UdpSender(t["send_host"], t["send_port"], t.get("pace_ms", 0.0))
        self._obj_counter = 0

    # -----------------------------------------------------------------------
    def process(self, obj: TransferObject) -> Dict[str, Any]:
        # S2 - layered inspection
        report = self.engine.inspect(obj)
        summary: Dict[str, Any] = {
            "object": obj.name,
            "size": obj.size,
            "risk": round(report.risk, 4),
            "band": report.band,
            "band_value": report.band_value,
            "detectors": [
                {"name": r.name, "score": round(r.score, 4),
                 "weight": r.weight, "available": r.available, "detail": r.detail}
                for r in report.results
            ],
        }

        if report.blocked:
            summary["status"] = "QUARANTINED"
            self.audit.append({
                "ts": time.time(), "epoch": "-", "object_name": obj.name,
                "object_size": obj.size, "band": report.band,
                "merkle_root": "", "signature": "", "side": "sender",
                "event": "quarantine", "risk": round(report.risk, 4),
            })
            return summary

        # S3 - adaptive integrity
        session = Session.create(self.policy_id)
        chunk_size = chunk_size_for_risk(report.band_value, self.c_max, self.c_min)
        chunks = chunk_object(obj.data, chunk_size)
        leaf_hashes = build_hash_chain(chunks, session.h0)
        root = merkle_root(leaf_hashes)

        manifest = Manifest(
            object_name=obj.name, object_size=obj.size,
            epoch=session.epoch, policy_id=self.policy_id, h0=session.h0,
            band=report.band, chunk_count=len(chunks),
            chunk_lengths=[c.length for c in chunks],
            merkle_root=root, signature=b"",
            hash_algo=self.cfg.integrity["hash_algorithm"],
        )
        manifest.signature = self.signer.sign(manifest.signing_payload())

        # audit + anchoring
        record = {
            "ts": time.time(), "epoch": session.epoch, "object_name": obj.name,
            "object_size": obj.size, "band": report.band,
            "merkle_root": root.hex(), "signature": manifest.signature.hex(),
            "side": "sender",
        }
        self.audit.append(record)
        anchored = self.anchor.maybe_anchor(report.band_value, {
            "epoch": session.epoch, "merkle_root": root.hex(),
            "band": report.band, "side": "sender",
        })

        # S4 - FEC + transmit
        payload = wire.pack_object(manifest, obj.data)
        self._obj_counter += 1
        symbols = self.fec.encode(payload, self._obj_counter)
        sent = self.sender.send_many(symbols)

        summary.update({
            "status": "SENT",
            "chunk_size": chunk_size,
            "chunk_count": len(chunks),
            "merkle_root": root.hex()[:16] + "...",
            "epoch": session.epoch,
            "fec_backend": self.fec.effective_backend,
            "symbols_sent": sent,
            "anchored": anchored,
            "anchor_interval_s": round(self.anchor.interval_for(report.band_value), 1),
        })
        return summary

    def close(self) -> None:
        self.sender.close()
