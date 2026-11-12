# RAIL - master runbook (two Kali VMs, total lockdown)

| Role | IP |
|---|---|
| **SENDER** - Network A | **10.0.2.8** |
| **RECEIVER** - Network B | **10.0.2.9** |

Seven phases, in order. Do not skip Phase 3 (the health check).

**Every new terminal starts with:**
```bash
cd ~/RAIL1 && source .venv/bin/activate
```
Your prompt must show `(.venv)`.

**Use the VirtualBox console window, not SSH.** Phase 5 makes SSH impossible.

---

# PHASE 0 - Copy the code

Copy the `RAIL1` folder to **both** VMs (including `railcds/` and the
emergency `unlock.sh`).

---

# PHASE 1 - Connectivity

### SENDER
```bash
ping -c 2 10.0.2.9
```
### RECEIVER
```bash
ping -c 2 10.0.2.8
```
Both must succeed. If not, fix the VirtualBox adapters first.

---

# PHASE 2 - Install (needs internet; do it all now)

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
Stop unless that prints `core OK`.
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
```bash
python3 scripts/train_anomaly.py --max-files 400
```

### RECEIVER (10.0.2.9) - minimal, no ML
```bash
cd ~/RAIL1 && source .venv/bin/activate
```
```bash
pip install --upgrade cryptography PyYAML numpy reedsolo raptorq
```

### SENDER - point at the receiver
```bash
sed -i 's/^\( *send_host:\).*/\1 "10.0.2.9"/' config/rail.yaml && grep send_host config/rail.yaml
```

### RECEIVER - the private key must not exist here
```bash
rm -f data/keys/sender_ed25519.key && ls data/keys/
```

### Toolchain for the optional driver layer (RECEIVER, before locking)
```bash
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-common arptables
```

---

# PHASE 3 - Health check (do not skip)

### SENDER
```bash
python3 -m railcds.cli doctor --role sender --peer 10.0.2.9
```

### RECEIVER
```bash
python3 -m railcds.cli doctor --role receiver --peer 10.0.2.8
```

`doctor` verifies the environment, every package, every model file, key
material, the configuration, all seven detectors, directories, network
reachability and enforcement state.

**Fix every `FAIL` before continuing.** Common ones:

| FAIL | Fix |
|---|---|
| `virtualenv active` | `source .venv/bin/activate` |
| `private key absent` (receiver) | `rm data/keys/sender_ed25519.key` |
| `self-send guard` | `send_host` points at this machine - correct it |
| `detectors available` < 4 | re-run the Phase 2 sender installs |

**Then check one thing by eye on both machines:**
```
[PASS] effective backend    <word>
```
**Both VMs must print the same word.** If they differ, pin both:
```bash
sed -i 's/^\( *backend:\) *"auto"/\1 "reedsolo"/' config/rail.yaml
```

---

# PHASE 4 - Pin the receiver's MAC (mandatory before a total lock)

Under total lockdown the receiver stops answering ARP. If the sender has not
already learnt its MAC address, no datagram will ever leave.

### RECEIVER - read its MAC and interface name
```bash
ip -brief link show
```

### SENDER - pin it permanently (substitute the MAC and interface)
```bash
sudo ip neigh replace 10.0.2.9 lladdr <RECEIVER_MAC> dev eth0 nud permanent
```
```bash
ip neigh show 10.0.2.9
```
Must show `PERMANENT`.

---

# PHASE 5 - LOCK (total: everything except the RAIL flow)

### SENDER (10.0.2.8)
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role sender --peer 10.0.2.9 --scope total --apply
```

### RECEIVER (10.0.2.9)
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role receiver --peer 10.0.2.8 --scope total --apply
```

### Optional - NIC/driver-level filter (RECEIVER)
```bash
sudo bash railcds/driver/load_xdp.sh attach receiver eth0 10.0.2.8 52080
```
Read the attach mode it reports: `xdpdrv` is true driver level, `xdpgeneric`
is a kernel-level fallback (what VirtualBox's emulated NIC gives).

### Prove the lock - run on BOTH; every one must FAIL
```bash
curl -m 5 https://www.google.com
```
```bash
ping -c 2 -W 2 8.8.8.8
```
```bash
sudo iptables -S | grep '^-P'
```
Expect `-P INPUT DROP`, `-P OUTPUT DROP`, `-P FORWARD DROP`.

### Prove there is no reverse channel - on the RECEIVER
```bash
ping -c 2 -W 2 10.0.2.8
```
Must FAIL. The receiver cannot reach Network A by any means.

---

# PHASE 6 - TRANSFER under RAIL

### RECEIVER - start first, leave this console running
```bash
python3 -m railcds.cli receive --out data/received
```
Wait for `listening on 0.0.0.0:52080` and `OS-level enforcement ACTIVE`.

### SENDER - its own console
```bash
python3 -m railcds.cli send --spool data/spool
```

Expected: high-risk objects `QUARANTINED` (never transmitted); the rest `SENT`;
the receiver printing `DELIVERED` with `verified: true`.

### Verify - RECEIVER, second console
```bash
cd ~/RAIL1 && source .venv/bin/activate
```
```bash
ls -l data/received/
```
```bash
python3 -m railcds.cli report
```

The report shows every Merkle root, signature, SHA-256, the append-only audit
chain verification, the ledger anchors written independently by both gateways,
and whether the delivered files are byte-identical to the source.

### SENDER - its side of the evidence
```bash
python3 -m railcds.cli report
```

### Optional demonstrations (SENDER)
```bash
python3 scripts/demo_local.py --loss 0.2
```
```bash
python3 scripts/demo_attacks.py
```
```bash
python3 scripts/evaluate.py
```
```bash
python3 -m pytest -q
```

---

# PHASE 7 - UNLOCK

### RECEIVER - detach the driver filter first, if you attached it
```bash
sudo bash railcds/driver/load_xdp.sh detach eth0
```

### SENDER
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role sender --peer 10.0.2.9 --release
```

### RECEIVER
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role receiver --peer 10.0.2.8 --release
```

### Confirm on both
```bash
ping -c 2 8.8.8.8
```

### If either machine is still cut off
```bash
sudo bash unlock.sh
```
No Python, no arguments. Restores policies, flushes rules, re-enables IPv6 and
ARP, detaches eBPF and restarts networking.

---

# Quick reference

| Task | Command |
|---|---|
| Health check | `railcds.cli doctor --role sender --peer <ip>` |
| Detector status | `railcds.cli detectors` |
| Score a file only | `railcds.cli inspect <file>` |
| Lock (total) | `lockdown --role R --peer <ip> --scope total --apply` |
| Lock status | `lockdown --role R --peer <ip> --status` |
| Unlock | `lockdown --role R --peer <ip> --release` |
| Emergency unlock | `sudo bash unlock.sh` |
| Receive | `railcds.cli receive --out data/received` |
| Send | `railcds.cli send --spool data/spool` |
| Evidence report | `railcds.cli report` |
| Audit chain check | `railcds.cli verify-log data/audit_receiver.jsonl` |

# What total lockdown proves - and what it does not

**Proves.** With default-DROP policies and one permitted rule, the only packet
that can cross is UDP from the sender to the receiver's RAIL port. The receiver
emits nothing at all: no ACK, no ICMP error, no ARP reply. This is enforced by
the kernel, independently of RAIL, and holds even if the Python process is
killed or compromised.

**Does not prove.** The rules live in each gateway's kernel; an attacker with
root on a gateway can remove them - which the paper's threat model already
places out of scope. The hypervisor also remains a shared component, so a VM
escape defeats the separation regardless of any firewall.
