# Testing RAIL yourself - sender and receiver configuration

Four escalating levels. Start at Level 0 on one machine; move to Level 2 (two
VMs on an isolated virtual network) for a full demonstration.

---

## Level 0 - one command, no network (5 minutes)

Proves the whole S1->S6 pipeline including inspection, adaptive integrity,
FEC recovery under loss, verification and dual audit logs.

```bash
py scripts/demo_local.py --loss 0.2
```

Expect: 3 objects DELIVERED, 3 QUARANTINED, chunk size shrinking and anchoring
interval falling as risk rises.

Then the three other checks:

```bash
py -m pytest -q
```

```bash
py scripts/demo_attacks.py
```

```bash
py scripts/evaluate.py --quick
```

Expect `26 passed`, `10/10 checks passed`, and the six evaluation sections.

---

## Level 1 - two terminals on one machine (real UDP sockets)

**Terminal 1 - receiver (plays Network B):**

```bash
py -m railcds.cli receive --timeout 60 --out data/received
```

**Terminal 2 - sender (plays Network A):**

```bash
py -m railcds.cli send --spool data/spool
```

Wait ~3 seconds after starting the receiver before sending - the sender loads
several hundred MB of ML models first, and a short receiver timeout can expire
during that load.

Verify afterwards:

```bash
py -m railcds.cli verify-log data/audit_sender.jsonl
```

```bash
py -m railcds.cli verify-log data/audit_receiver.jsonl
```

---

## Level 2 - two VMs on an isolated virtual network (recommended)

No special hardware. VirtualBox + Vagrant, two VMs on a private internal
network. `deploy/vagrant/Vagrantfile` already defines them:

| VM | Role | IP |
|---|---|---|
| `netA` | sender / Network A | 10.20.0.10 |
| `netB` | receiver / Network B | 10.20.0.20 |

```bash
cd deploy/vagrant && vagrant up
```

Then `vagrant ssh netB` to run the receiver and `vagrant ssh netA` to send.

The one-way property is enforced *below* the application by `iptables`, so it
does not depend on the transfer program behaving correctly - this matters,
because the paper's whole argument is that enforcement should not rest on a
single component.

---

# Configuration: sender vs receiver

This is the part that differs per side. Both machines use the same
`config/rail.yaml` file, but **each side only reads part of it**.

## What the SENDER (Network A) needs

**Software - the full stack:**

```bash
py -m pip install cryptography PyYAML numpy scikit-learn lightgbm lief yara-python python-magic-bin reedsolo joblib
py -m pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git" "signify==0.5.2"
py -m pip install torch --index-url https://download.pytorch.org/whl/cpu
```

**Models - all of them** (inspection happens only here):

```bash
py scripts/download_models.py --deep
py scripts/train_anomaly.py
```

**Keys - generate here, and the private key never leaves:**

```bash
py scripts/gen_keys.py
```

**Config keys the sender actually reads:**

```yaml
policy:
  id: "rail-policy-2026.08"      # MUST match receiver

inspection:                       # sender-only; receiver ignores all of this
  block_threshold: 0.90
  detectors: {...}

integrity:
  chunk_max_bytes: 1048576        # sender-only (Eq. 2)
  chunk_min_bytes: 16384          # sender-only
  hash_algorithm: "sha256"
  risk_bands: 4                   # MUST match receiver

fec:                              # sender-only; receiver reads params from
  backend: "auto"                 #   each symbol header, so it self-adapts
  symbol_size: 1024
  overhead: 0.5                   # must exceed worst-case link loss

transport:
  send_host: "10.20.0.20"         # <-- the RECEIVER's IP
  send_port: 52080                # <-- must equal receiver's bind_port
  pace_ms: 0.5

crypto:
  sender_private_key: "data/keys/sender_ed25519.key"   # stays on A

audit:
  sender_log: "data/audit_sender.jsonl"
```

### Lock the boundary down (both sides)

The Python code alone does not stop SSH/SMB/HTTP/ICMP between the hosts. On
each machine run, as Administrator/root:

```bash
py -m railcds.cli lockdown --role sender --peer 10.20.0.20 --apply
```

Omit `--apply` first to see the exact rules. `--release` undoes them,
`--status` reports whether enforcement is live. See `docs/NETWORK_HARDENING.md`.

## What the RECEIVER (Network B) needs

**Software - minimal. No ML libraries, no PyTorch, no models.**

```bash
py -m pip install cryptography PyYAML numpy
```

That is the entire dependency list. Verified: with the whole
`railcds/inspection/` directory **deleted**, no `models/` directory, and no
private key, the receiver still accepted and verified transfers correctly.

**Keys - public key only:**

Copy *only* `data/keys/sender_ed25519.pub` from A to B. Never copy the `.key`.

**Config keys the receiver actually reads:**

```yaml
policy:
  id: "rail-policy-2026.08"      # MUST match sender, else every object REJECTED

integrity:
  risk_bands: 4                   # MUST match sender; band is range-checked

anchoring:                        # receiver anchors independently
  t_min_seconds: 5
  t_max_seconds: 300
  gamma: 2.0
  backend: "file"
  ledger_path: "data/ledger.jsonl"

transport:
  bind_host: "0.0.0.0"
  bind_port: 52080                # <-- must equal sender's send_port
  mtu: 1400

crypto:
  sender_public_key: "data/keys/sender_ed25519.pub"    # public key ONLY

audit:
  receiver_log: "data/audit_receiver.jsonl"
```

The receiver ignores `inspection.*`, `integrity.chunk_*`, `fec.*`,
`crypto.sender_private_key` and `transport.send_*` entirely.

## The four settings that MUST match

Get these wrong and every object is rejected:

| Setting | Why | Failure symptom |
|---|---|---|
| `policy.id` | Bound into H₀ and the signature | `REJECTED - policy mismatch` |
| `integrity.risk_bands` | Receiver range-checks the band | `REJECTED - band out of range` |
| sender `send_port` = receiver `bind_port` | Datagrams must arrive | silence; nothing delivered |
| keypair | Public key must match the private key | `REJECTED - sig_ok=False` |

Chunk sizes, FEC parameters and detector settings do **not** need to match -
chunk lengths travel in the manifest and FEC parameters travel in each symbol
header, so the receiver adapts automatically.

---

## Environment-variable overrides

Useful for VMs and containers without editing YAML on each host:

```bash
RAIL_SEND_HOST=10.20.0.20 RAIL_SEND_PORT=52080 py -m railcds.cli send --spool data/spool
```

```bash
RAIL_BIND_HOST=0.0.0.0 RAIL_BIND_PORT=52080 py -m railcds.cli receive --timeout 60
```

---

## Test checklist

Work through these to demonstrate the architecture end to end.

| # | Test | Command | Expected |
|---|---|---|---|
| 1 | Detectors load | `py -m railcds.cli detectors` | 7 available on A |
| 2 | Risk scoring | `py -m railcds.cli inspect data/spool/*` | risk rises with suspicion |
| 3 | Adaptive chunking | `py scripts/demo_local.py` | chunk size falls as band rises |
| 4 | Adaptive anchoring | same output | interval falls as band rises |
| 5 | Quarantine | same output | high-risk objects never transmitted |
| 6 | FEC under loss | `py scripts/demo_local.py --loss 0.3` | still delivered |
| 7 | Delivered integrity | `cmp data/spool/x data/received/x` | byte-identical |
| 8 | Audit chains | `py -m railcds.cli verify-log <log>` | chain intact |
| 9 | Dual anchoring | `cat data/ledger.jsonl` | same root from both sides |
| 10 | Threat model | `py scripts/demo_attacks.py` | 10/10 |
| 11 | Metrics | `py scripts/evaluate.py` | see `docs/RESULTS.md` |

### Negative tests worth demonstrating

**Wrong policy id** - set a different `policy.id` on B and send:
expect `REJECTED - policy mismatch` on every object.

**Wrong key** - regenerate keys on A without copying the new `.pub` to B:
expect `REJECTED - sig_ok=False`.

**Tamper** - flip a byte in a delivered file and re-verify its Merkle root:
the chain breaks. `scripts/demo_attacks.py` automates this (test T3).

**Loss beyond the FEC margin** - `py scripts/demo_local.py --loss 0.6`:
objects are lost outright, because a one-way link has no retransmission.

---

## Troubleshooting

**Nothing arrives at the receiver.** Ports must match; start the receiver
first and allow ~3 s for sender model loading; on Windows allow Python through
the firewall; on Linux check `iptables`/`ufw`. Confirm reachability with
`nc -u -l 52080` on B and `echo test | nc -u 10.20.0.20 52080` on A.

**Everything is REJECTED.** Almost always `policy.id` mismatch or a stale
public key. Compare both configs and re-copy the `.pub`.

**Detector shows UNAVAILABLE.** Run `py scripts/download_models.py --deep`;
for the deep models confirm `pip install torch`. Missing models degrade
gracefully - the other detectors carry the decision.

**Everything scores as high risk.** Detector weights and `block_threshold` are
policy, not universal constants. Profile against *your* benign traffic first -
`py scripts/evaluate.py` reports a per-detector false-alarm table - then tune
weights and retrain the anomaly model on representative data.

**Large objects are slow.** Expected on this prototype: ~0.12 MB/s end-to-end,
dominated by pure-Python FEC and CPU ML inference. See `docs/RESULTS.md` §E1.
