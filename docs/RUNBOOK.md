# RAIL runbook - install, provision, run

Commands are shown for Windows (PowerShell, using the `py` launcher). On
Linux/macOS use `python3` instead of `py`. Run everything from the project root
(`RAIL/`).

---

## 1. Requirements

* Python 3.11+ (tested on 3.13). `py --version`
* ~1 GB free disk (mostly ML deps). Internet **once**, to install packages and
  fetch models; RAIL itself makes no network calls at inspection time.

## 2. Install dependencies

```bash
py -m pip install cryptography PyYAML numpy scikit-learn lightgbm lief yara-python python-magic-bin reedsolo joblib
```

Offline ML classifier (EMBER2024):

```bash
py -m pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git"
py -m pip install "signify==0.5.2"
```

(RaptorQ is optional; if `pip install raptorq` fails to build, RAIL uses its
built-in Reed-Solomon erasure code automatically.)

## 3. Provision models + keys + sample objects

```bash
py scripts/download_models.py        # bundled YARA rules + EMBER2024 model
py scripts/train_anomaly.py          # trains the local anomaly model
py scripts/gen_keys.py               # Ed25519 keypair (private stays on sender)
py scripts/make_test_object.py       # writes harmless samples to data/spool/
```

Verify:

```bash
py -m railcds.cli detectors          # all enabled detectors should be "available"
```

## 4. Try it - single machine

**In-process demo** (shows adaptive chunking, blocking, FEC under loss):

```bash
py scripts/demo_local.py --loss 0.2
```

**Real UDP path**, two terminals:

```bash
# terminal 1 (receiver / Network B)
py -m railcds.cli receive --out data/received
# terminal 2 (sender / Network A)
py -m railcds.cli send --spool data/spool
```

Inspect a single object without sending it:

```bash
py -m railcds.cli inspect data/spool/polyglot.pdf
```

## 5. Verify integrity artefacts

```bash
py -m railcds.cli verify-log data/audit_sender.jsonl
py -m railcds.cli verify-log data/audit_receiver.jsonl
type data\ledger.jsonl               # sender & receiver anchor the same roots
```

Confirm a delivered file is byte-identical:

```bash
fc /b data\spool\benign.txt data\received\benign.txt
```

## 6. Run the tests

```bash
py -m pip install pytest
py -m pytest -q
```

Expected: `26 passed`.

### 6b. Security demonstration (threat model)

Mounts a concrete attack for each adversary objective in Section II of the paper
and reports whether RAIL detects or bounds it:

```bash
py scripts/demo_attacks.py
```

Expected: `10/10 checks passed` - covering reverse flow (T1), malicious payload
and polyglot injection (T2), post-inspection corruption (T3), replay/reordering
and signature forgery (T4), and the covert-channel bound (T5).

## 7. Two-VM / virtual-network / Docker deployment

See `deploy/README_NETWORK.md`. Short version:

```bash
# Vagrant + VirtualBox: two VMs on a one-way private network
cd deploy/vagrant && vagrant up
# ... then `vagrant ssh netB` (receive) and `vagrant ssh netA` (send)

# or Docker: one-way enforced by network topology (sender -> diode -> receiver)
cd deploy/docker && docker compose build && docker compose up -d receiver diode
docker compose run --rm sender python -m railcds.cli send --spool data/spool
```

---

## Tuning cheatsheet (`config/rail.yaml`)

| Want to... | Change |
|----------|--------|
| Block more/less aggressively | `inspection.block_threshold` (θ_blk) |
| Change a detector's influence | `inspection.detectors.<name>.weight` |
| Disable/enable a detector | `inspection.detectors.<name>.enabled` |
| Coarser/finer chunking range | `integrity.chunk_max_bytes` / `chunk_min_bytes` |
| More/fewer covert-channel bands | `integrity.risk_bands` (B) |
| Anchor more/less often | `anchoring.t_min_seconds` / `t_max_seconds` / `gamma` |
| Tolerate more packet loss | `fec.overhead` (raise above expected loss) |
| Point sender at receiver | `transport.send_host` / `send_port` (or `RAIL_SEND_HOST` env) |

## Troubleshooting

* **`detectors` shows `ember2024_ml UNAVAILABLE`** - run
  `download_models.py --ember2024`; ensure `signify==0.5.2` is installed.
* **EICAR sample disappears** - host antivirus quarantined it. RAIL's samples
  use only the harmless EICAR *marker*; if you add a real one, use an isolated
  VM with AV off (see `deploy/README_NETWORK.md` §5).
* **Receiver seems to miss a transfer** - start the receiver first and give it a
  moment; the sender loads ML models (a few seconds) before its first send. In
  production the receiver runs continuously.
* **`raptorq` install fails** - ignore it; the Reed-Solomon backend is used.
