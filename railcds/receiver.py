"""Receiver-side gateway (Network B): Stages S4' -> S6 plus the audit path.

Per completed object:
    S4' collect FEC symbols and reconstruct the payload
    S5  recompute the linked hash chain from the manifest's H0, rebuild the
        Merkle root, check it equals the signed root and verify the Ed25519
        signature over (root, epoch, band, policy); reject on any mismatch or on
        a replayed epoch (session-binding replay defence)
    S6  append to the independent audit log, anchor periodically, and
        re-originate (deliver) the object on the destination network
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set

from . import wire
from .anchoring import AnchorManager, Ledger
from .auditlog import AuditLog
from .config import Config
from .crypto import Verifier
from .fec import FecDecoder
from .hashchain import build_hash_chain
from .merkle import merkle_root
from .protocol_break import ProtocolBreak
from .session import derive_h0
from .transport import UdpReceiver


class ReceiverGateway:
    def __init__(self, cfg: Config, out_dir: Optional[Path] = None,
                 receiver: Optional[UdpReceiver] = None,
                 on_result: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self.cfg = cfg
        self.verifier = Verifier.from_file(cfg.resolve(cfg.crypto["sender_public_key"]))
        self.decoder = FecDecoder()
        self.audit = AuditLog(cfg.resolve(cfg.audit["receiver_log"]), side="receiver")
        self.policy_id = cfg.policy_id
        self.bands = int(cfg.integrity["risk_bands"])
        self._seen_epochs: Set[str] = set()
        self.on_result = on_result

        ledger = Ledger(
            backend=cfg.anchoring["backend"],
            path=cfg.resolve(cfg.anchoring["ledger_path"]),
            endpoint=cfg.anchoring.get("endpoint"),
        )
        self.anchor = AnchorManager(cfg.anchoring, ledger)

        out = out_dir or (cfg.root / "data" / "received")
        self.pb = ProtocolBreak(out_dir=out)

        t = cfg.transport
        self.receiver = receiver or UdpReceiver(t["bind_host"], t["bind_port"], t.get("mtu", 1500))

    # -----------------------------------------------------------------------
    def _handle_datagram(self, datagram: bytes) -> None:
        obj_id = self.decoder.add(datagram)
        if obj_id is None:
            return
        # Everything below is driven by bytes that arrived over a one-way link:
        # the gateway cannot ask for a retransmission and must never terminate
        # because of a malformed or hostile object. Reject and keep serving.
        try:
            payload = self.decoder.reconstruct(obj_id)
        except Exception as exc:                      # noqa: BLE001
            self.decoder.drop(obj_id)
            result = {"object": "?", "status": "REJECTED",
                      "reason": f"reconstruction failed: "
                                f"{type(exc).__name__}: {exc}"}
            if self.on_result:
                self.on_result(result)
            return
        else:
            self.decoder.drop(obj_id)

        try:
            result = self._verify_and_deliver(payload)
        except Exception as exc:                      # noqa: BLE001
            result = {"object": "?", "status": "REJECTED",
                      "reason": f"malformed object: "
                                f"{type(exc).__name__}: {exc}"}
        if self.on_result:
            self.on_result(result)

    def _verify_and_deliver(self, payload: bytes) -> Dict[str, Any]:
        manifest, chunks = wire.unpack_object(payload)
        result: Dict[str, Any] = {
            "object": manifest.object_name, "size": manifest.object_size,
            "epoch": manifest.epoch, "band": manifest.band,
        }

        # --- replay / session-binding check --------------------------------
        if manifest.epoch in self._seen_epochs:
            result["status"] = "REJECTED"
            result["reason"] = "replayed epoch"
            self._log(manifest, verified=False, event="replay")
            return result
        self._seen_epochs.add(manifest.epoch)

        # --- policy / band sanity ------------------------------------------
        if manifest.policy_id != self.policy_id:
            result["status"] = "REJECTED"
            result["reason"] = f"policy mismatch ({manifest.policy_id})"
            self._log(manifest, verified=False, event="policy_mismatch")
            return result
        if not (0 <= manifest.band < self.bands):
            result["status"] = "REJECTED"
            result["reason"] = "band out of range"
            self._log(manifest, verified=False, event="bad_band")
            return result

        # --- S5: recompute chain + Merkle root, verify signature -----------
        leaf_hashes = build_hash_chain(chunks, manifest.h0)
        root = merkle_root(leaf_hashes)
        root_ok = (root == manifest.merkle_root)
        sig_ok = self.verifier.verify(manifest.signature, manifest.signing_payload())

        if not (root_ok and sig_ok):
            result["status"] = "REJECTED"
            result["reason"] = f"root_ok={root_ok} sig_ok={sig_ok}"
            self._log(manifest, verified=False, event="verify_fail")
            return result

        # --- S6: audit, anchor, re-originate -------------------------------
        self._log(manifest, verified=True, event="delivered")
        band_value = manifest.band / self.bands
        self.anchor.maybe_anchor(band_value, {
            "epoch": manifest.epoch, "merkle_root": root.hex(),
            "band": manifest.band, "side": "receiver",
        })
        data = b"".join(c.data for c in chunks)
        dest = self.pb.reoriginate(manifest.object_name, data)
        # Report the full integrity values so the operator can compare them
        # against the sender's audit log.
        result.update({
            "status": "DELIVERED",
            "verified": True,
            "path": str(dest),
            "sha256": hashlib.sha256(data).hexdigest(),
            "merkle_root": root.hex(),
            "merkle_root_matches_signed": root_ok,
            "signature_valid": sig_ok,
            "signature": manifest.signature.hex(),
            "h0": manifest.h0.hex(),
            "policy_id": manifest.policy_id,
            "chunk_count": manifest.chunk_count,
            "chunk_lengths": manifest.chunk_lengths[:8],
            "hash_algo": manifest.hash_algo,
        })
        return result

    def _log(self, manifest, verified: bool, event: str) -> None:
        self.audit.append({
            "ts": time.time(), "epoch": manifest.epoch,
            "object_name": manifest.object_name, "object_size": manifest.object_size,
            "band": manifest.band, "merkle_root": manifest.merkle_root.hex(),
            "signature": manifest.signature.hex(), "side": "receiver",
            "verified": verified, "event": event,
        })

    # -----------------------------------------------------------------------
    def serve(self, idle_timeout: Optional[float] = None) -> None:
        self.receiver.recv_loop(self._handle_datagram, idle_timeout=idle_timeout)

    def close(self) -> None:
        self.receiver.close()
