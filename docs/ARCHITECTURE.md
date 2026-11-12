# RAIL architecture - paper-to-code map

This implementation follows the six-stage pipeline (S1-S6) and the seven
equations of the paper *"Software-Based Data Diodes for Trusted Network
Integration: A Survey and a Risk-Adaptive Multilayer Architecture"* one-to-one.

```
 Network A (source)                                   Network B (destination)
 ┌───────────────────────┐                            ┌───────────────────────┐
 │ S1 Protocol Separation│  protocol_break.py         │ S6 Re-origination     │
 │ S2 Layered Inspection │  inspection/  (Eq.1)       │ S5 Integrity Verify   │
 │ S3 Adaptive Integrity │  chunker/hashchain/merkle  │ S4' FEC Decoding      │
 │ S4 FEC Encoding       │  fec.py       (Eq.2,3,5)   │        ▲              │
 └──────────┬────────────┘                            └────────┼──────────────┘
            │  one-way UDP + FEC symbols   (transport.py)      │
            └──────────────────────────────────────────────────┘
                      Append-only audit log, anchored every T(r)   (Eq.4, Eq.6)
```

## Stage -> module

| Stage | What it does | Module(s) |
|------|---------------|-----------|
| **S1** | Terminate incoming session, extract application object | `protocol_break.ProtocolBreak.extract_file` |
| **S2** | Run detectors, compute risk `r(O)`, block if `≥ θ_blk`, quantise to band | `inspection/engine.py`, `risk.py`, `quantize.py` |
| **S3** | Chunk `c(r)`, linked hash chain, session H0, Merkle root, sign, audit, anchor | `chunker.py`, `hashchain.py`, `session.py`, `merkle.py`, `crypto.py`, `auditlog.py`, `anchoring.py` |
| **S4** | FEC-encode manifest+chunks, transmit one-way | `fec.py`, `wire.py`, `transport.UdpSender` |
| **S4'** | Collect symbols, reconstruct payload | `fec.FecDecoder`, `transport.UdpReceiver` |
| **S5** | Recompute chain+root, verify signature & root, replay check | `receiver.ReceiverGateway._verify_and_deliver` |
| **S6** | Append to independent log, anchor, re-originate (deliver) | `receiver.py`, `protocol_break.reoriginate` |

Orchestration: `sender.SenderGateway.process` (S1-S4), `receiver.ReceiverGateway`
(S4'-S6).

## Equation -> code

| Eq. | Meaning | Where |
|-----|---------|-------|
| **1** | `r(O) = 1 − Π(1 − wᵢ·sᵢ(O))` - Noisy-OR risk | `risk.noisy_or` |
| **2** | `c(r) = c_max·(c_min/c_max)^r` - adaptive chunk size | `chunker.chunk_size_for_risk` |
| **3** | `Hᵢ = SHA-256(H_{i-1} ∥ seqᵢ ∥ lenᵢ ∥ mᵢ)` - hash chain | `hashchain.chunk_hash` |
| **4** | `T(r) = T_min + (T_max−T_min)(1−r)^γ` - anchoring interval | `anchoring.anchoring_interval` |
| **5** | `r̃ = ⌊rB⌋/B` - risk-band quantisation | `quantize.quantise` |
| **6** | `C ≤ λ·log₂B` - covert-channel capacity bound | `quantize.channel_capacity_bound` |
| H0 | `H0 = SHA-256("RAIL-H0" ∥ nonce ∥ policy_id)` - session binding | `session.derive_h0` |

## Security properties realised

* **One-way flow** - send-only/recv-only sockets (`transport.py`), reinforced by
  firewall/topology enforcement in `deploy/` (Section 0 of `deploy/README_NETWORK.md`).
* **No transport state crosses the boundary** - only `wire.pack_object` output
  (manifest JSON + object bytes, FEC-encoded) is transmitted; the continuous
  risk score never crosses, only the quantised band (covert-channel control).
* **Tamper evidence** - the linked hash chain + Merkle root mean any chunk edit,
  reorder or boundary shift changes the root (`test_merkle_hashchain.py`); the
  root is Ed25519-signed, so it cannot be forged without the sender key.
* **Replay defence** - H0 is derived from a per-session nonce and the receiver
  rejects a repeated epoch (`ReceiverGateway._seen_epochs`), realising the
  paper's session binding.
* **Independent dual logs** - sender and receiver each keep an append-only,
  self-chained log (`auditlog.py`) and anchor the same Merkle roots separately,
  so the two can be compared during audit even if one gateway is compromised.
* **Bounded covert channel** - chunk size and anchoring cadence are driven by
  the *quantised* band (`B` values), capping the channel at `log₂B` bits/object.

## Data that crosses the wire

`wire.pack_object` ->  `[4-byte manifest length][manifest JSON][object bytes]`,
then FEC-encoded into self-describing symbols (`fec.HEADER`). The manifest
(`models.Manifest`) carries: object name/size, epoch, policy id, H0, quantised
band, chunk count/lengths, Merkle root, Ed25519 signature. Nothing else - no
sockets state, no continuous score.
