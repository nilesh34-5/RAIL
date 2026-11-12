# RAIL - complete run sequence (two Kali VMs)

| Role | IP |
|---|---|
| **SENDER** - Network A | **10.0.2.8** |
| **RECEIVER** - Network B | **10.0.2.9** |

Run the phases in order. Every new terminal needs
`cd ~/RAIL1 && source .venv/bin/activate` first - the `(.venv)` prefix must be
visible in your prompt.

---

## PHASE 0 - Connectivity check

**SENDER**
```bash
ping -c 2 10.0.2.9
```

**RECEIVER**
```bash
ping -c 2 10.0.2.8
```

Both must succeed. If not, fix the VirtualBox adapters before continuing -
nothing else will work.

---

## PHASE 1 - Install

### SENDER (10.0.2.8) - full inspection stack

```bash
cd ~/RAIL1 && source .venv/bin/activate
```
```bash
pip install --upgrade cryptography PyYAML numpy reedsolo scikit-learn joblib lightgbm yara-python python-magic lief
```
```bash
python3 -c "import cryptography, yaml, numpy, yara, sklearn, lightgbm; print('core OK')"
```
Do not continue until that prints `core OK`.

```bash
pip install raptorq
```
```bash
pip install torch --extra-index-url https://download.pytorch.org/whl/cpu
```
```bash
pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git" && pip install "signify==0.5.2"
```
```bash
python3 scripts/download_models.py --deep
```

### RECEIVER (10.0.2.9) - minimal, no ML

```bash
cd ~/RAIL1 && source .venv/bin/activate
```
```bash
pip install --upgrade cryptography PyYAML numpy reedsolo raptorq
```
```bash
python3 -c "import cryptography, yaml, numpy; print('core OK')"
```

---

## PHASE 2 - Configure

### SENDER - point at the receiver
```bash
sed -i 's/^\( *send_host:\).*/\1 "10.0.2.9"/' config/rail.yaml && grep send_host config/rail.yaml
```
Must print `send_host: "10.0.2.9"`.

### SENDER - confirm detectors
```bash
python3 -m railcds.cli detectors
```
Expect 7 detectors. Note any `UNAVAILABLE`.

### RECEIVER - the private key must not exist here
```bash
rm -f data/keys/sender_ed25519.key && ls data/keys/
```
Only `sender_ed25519.pub` should remain.

### BOTH - the FEC backends must match
```bash
python3 -c "from railcds.fec import FEC; print(FEC(backend='auto').effective_backend)"
```
If the two VMs print different words, pin both:
```bash
sed -i 's/^\( *backend:\) *"auto"/\1 "reedsolo"/' config/rail.yaml
```

---

## PHASE 3 - LOCK the boundary (before any transfer)

Receiver first, then sender.

### RECEIVER (10.0.2.9)
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role receiver --peer 10.0.2.8 --apply
```

### SENDER (10.0.2.8)
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role sender --peer 10.0.2.9 --apply
```

### Prove it is one-way - on RECEIVER
```bash
ping -c 2 -W 2 10.0.2.8
```
**This must FAIL.** The receiver can no longer reach Network A.

```bash
sudo iptables -L OUTPUT -v -n | grep 10.0.2.8
```
Shows the DROP rule and its packet counter.

---

## PHASE 4 - TRANSFER through the locked boundary

### RECEIVER (10.0.2.9) - start first, leave running
```bash
python3 -m railcds.cli receive --out data/received
```
Wait for `listening on 0.0.0.0:52080`. It should now say
`OS-level enforcement ACTIVE`.

### SENDER (10.0.2.8) - in its own terminal
```bash
python3 -m railcds.cli send --spool data/spool
```

Expected: high-risk objects `QUARANTINED` (never transmitted), the rest `SENT`,
and the receiver printing `DELIVERED` with `verified: true`.

---

## PHASE 5 - VERIFY

### RECEIVER - second terminal
```bash
cd ~/RAIL1 && source .venv/bin/activate
```
```bash
ls -l data/received/
```
```bash
python3 -m railcds.cli report
```

### SENDER
```bash
python3 -m railcds.cli report
```

The report shows every Merkle root, signature, SHA-256, the append-only audit
chain verification, the ledger anchors written independently by both gateways,
and whether the delivered files are byte-identical to the source.

### Optional - adaptive behaviour and the threat model (SENDER)
```bash
python3 scripts/demo_local.py --loss 0.2
```
```bash
python3 scripts/demo_attacks.py
```
```bash
python3 scripts/evaluate.py
```

---

## PHASE 6 - UNLOCK

### SENDER (10.0.2.8)
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role sender --peer 10.0.2.9 --release
```

### RECEIVER (10.0.2.9)
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role receiver --peer 10.0.2.8 --release
```

### Confirm - on RECEIVER
```bash
ping -c 2 10.0.2.8
```
Should succeed again.

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | venv not active | `source .venv/bin/activate`, check for `(.venv)` |
| Nothing delivered | receiver not running, or started after the sender | start the receiver first |
| Every object `REJECTED` | `policy.id` mismatch or stale public key | compare `config/rail.yaml`; re-copy the `.pub` |
| Objects sent that should be blocked | ML detectors unavailable | re-run Phase 1 sender steps |
| `ping` succeeds after locking | rules did not apply | re-run with `sudo`, check for errors |
| Locked out of the VM | should not happen - the lock is peer-scoped | Phase 6 release |

**Note on scope.** The lock blocks traffic *between these two VMs* only; each
keeps its own internet. With a single NIC per VM, ARP is **not** blocked
(blocking it would also sever the default gateway), so a residual layer-2
reverse channel remains. To close it, give each VM a second adapter on a VirtualBox
Internal Network and use `--scope strict --iface eth1`.
